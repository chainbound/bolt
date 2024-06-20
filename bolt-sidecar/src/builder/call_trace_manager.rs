use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    pin::Pin,
    task::Poll,
};

use alloy_eips::BlockId;
use alloy_primitives::{Address, BlockNumber, U64};
use alloy_rpc_types::{
    state::{AccountOverride, StateOverride},
    TransactionRequest,
};
use alloy_rpc_types_trace::geth::{
    AccountState, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
    GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace, PreStateFrame, TraceResult,
};
use alloy_transport::TransportResult;
use futures::{stream::FuturesOrdered, Future, StreamExt};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use crate::RpcClient;

/// Commands to interact with the [CallTraceManager] actor
#[derive(Debug)]
pub enum TraceCommand {
    /// Request to trace a transaction's execution on a remote RPC,
    /// considering the given block as starting point and accumulating
    /// the results on a state diff map.
    AddTrace {
        transaction: TransactionRequest,
        block: BlockNumber,
    },
    /// Request to get the accumulated state diffs for a bundle of transactions
    /// that were previously simulated on the given block.
    ///
    /// The result is sent back through a response channel as soon as the last
    /// pending trace request for that block has been processed.
    FetchAccumulatedDiffs {
        block: BlockNumber,
        res: oneshot::Sender<Option<StateOverride>>,
    },
}

#[derive(Debug, Clone)]
pub struct CallTraceHandle {
    cmd_tx: mpsc::Sender<TraceCommand>,
}

impl CallTraceHandle {
    pub async fn add_trace(&self, transaction: TransactionRequest, block: BlockNumber) {
        let _ = self
            .cmd_tx
            .send(TraceCommand::AddTrace { transaction, block })
            .await;
    }

    pub async fn fetch_accumulated_diffs(&self, block: BlockNumber) -> Option<StateOverride> {
        let (res_tx, res_rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(TraceCommand::FetchAccumulatedDiffs { block, res: res_tx });

        res_rx.await.unwrap()
    }
}

#[derive(Debug)]
pub struct CallTraceManager {
    rpc: RpcClient,
    cmd_rx: mpsc::Receiver<TraceCommand>,
    pending_traces: FuturesOrdered<TraceFuture>,
    trace_request_queue: HashMap<BlockNumber, VecDeque<TransactionRequest>>,
    response_queue: HashMap<BlockNumber, oneshot::Sender<Option<StateOverride>>>,
    accumulated_state_diffs: HashMap<BlockNumber, StateOverride>,
}

type TraceFuture = JoinHandle<(BlockNumber, TransportResult<GethTrace>)>;

impl CallTraceManager {
    /// Creates a new [CallTraceManager] instance, which will listen for incoming
    /// trace requests and process them in the background using the given RPC client.
    pub fn new(url: &str) -> (Self, CallTraceHandle) {
        let rpc = RpcClient::new(url);
        let (cmd_tx, cmd_rx) = mpsc::channel(512);

        (
            Self {
                rpc,
                cmd_rx,
                trace_request_queue: Default::default(),
                pending_traces: Default::default(),
                response_queue: Default::default(),
                accumulated_state_diffs: Default::default(),
            },
            CallTraceHandle { cmd_tx },
        )
    }

    /// Runs the [CallTraceManager] actor, processing incoming trace requests and
    /// accumulating the resulting state diffs for each block in the background.
    pub async fn run(mut self) {
        tokio::select! {
            Some(request) = self.cmd_rx.recv() => {
                self.handle_new_trace_command(request);
            },
            Some(Ok((block, trace_result))) = self.pending_traces.next() => {
                self.handle_trace_result(block, trace_result);
            }
        }
    }

    fn handle_new_trace_command(&mut self, cmd: TraceCommand) {
        match cmd {
            TraceCommand::AddTrace { transaction, block } => {
                // TODO: handle the case where the block is in the future.
                // Requires a execution block interval ticker.

                // Try to start the trace call in the background if
                // there is no pending task
                if self.pending_traces.is_empty() {
                    self.start_new_trace_call_with_overrides(transaction, block);
                } else {
                    // Otherwise, add the transaction to the queue to be processed
                    // in order for the given block
                    self.trace_request_queue
                        .entry(block)
                        .or_default()
                        .push_back(transaction);
                }
            }
            TraceCommand::FetchAccumulatedDiffs { block, res } => {
                if self.pending_traces.is_empty() {
                    // If there are no pending traces for the given block, and the
                    // accumulated state diffs are already available, send the result
                    if let Some(diffs) = self.accumulated_state_diffs.remove(&block) {
                        let _ = res.send(Some(diffs));
                    } else {
                        let _ = res.send(None);
                    }
                } else {
                    // Otherwise, store the response channel to be used later once the last
                    // pending trace request for that block has been processed and the diffs
                    // are available.
                    self.response_queue.insert(block, res);
                }
            }
        }
    }

    fn handle_trace_result(&mut self, block: BlockNumber, result: TransportResult<GethTrace>) {
        match result {
            Ok(trace) => {
                tracing::debug!(block = block, "RPC trace call completed");

                let Ok(PreStateFrame::Default(trace_state)) = trace.try_into_pre_state_frame()
                else {
                    tracing::error!("Failed to extract pre-state frame from trace result");
                    return;
                };

                // Store the updated accumulated state diffs for the given block
                let acc_state_diffs = self.accumulated_state_diffs.entry(block).or_default();
                for (address, account_state) in trace_state.0 {
                    let account_override = acc_state_diffs.entry(address).or_default();
                    merge_account_state_in_overrides(account_override, account_state);
                }

                // If there are more pending trace requests for the same block, process the next one
                if let Some(transactions) = self.trace_request_queue.get_mut(&block) {
                    if let Some(transaction) = transactions.pop_front() {
                        self.start_new_trace_call_with_overrides(transaction, block);
                        return;
                    }
                }

                // If there are no more transactions to process for this block,
                // send the accumulated state diffs to the response channel if there is
                // one waiting for it
                if let Some(res) = self.response_queue.remove(&block) {
                    let _ = res.send(Some(acc_state_diffs.clone()));
                    self.accumulated_state_diffs.remove(&block);
                }
            }
            Err(err) => {
                tracing::error!(err = ?err, "RPC error while tracing transaction");

                // For now, just log the error and continue processing the next trace request
                // for the same block, if there is one.
                if let Some(transactions) = self.trace_request_queue.get_mut(&block) {
                    if let Some(transaction) = transactions.pop_front() {
                        self.start_new_trace_call_with_overrides(transaction, block);
                    }
                }

                if let Some(res) = self.response_queue.remove(&block) {
                    let _ = res.send(None);
                    self.accumulated_state_diffs.remove(&block);
                }
            }
        }
    }

    fn start_new_trace_call_with_overrides(
        &mut self,
        transaction: TransactionRequest,
        block: BlockNumber,
    ) {
        let rpc = self.rpc.clone();
        let state_override = self
            .accumulated_state_diffs
            .get(&block)
            .cloned()
            .unwrap_or_default();

        let tracing_options = get_trace_options_with_override(state_override);
        self.pending_traces.push_back(tokio::spawn(async move {
            (
                block,
                rpc.debug_trace_call(transaction, Some(block), Some(tracing_options))
                    .await,
            )
        }));
    }
}

fn get_trace_options_with_override(state_override: StateOverride) -> GethDebugTracingCallOptions {
    let mut opts = GethDebugTracingOptions::default().with_tracer(
        GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::PreStateTracer),
    );

    opts.config = GethDefaultTracingOptions::default()
        .with_disable_storage(false)
        .with_disable_memory(true)
        .with_disable_return_data(true)
        .with_disable_stack(true);

    GethDebugTracingCallOptions::default()
        .with_tracing_options(opts)
        .with_state_overrides(state_override)
}

fn merge_account_state_in_overrides(account_override: &mut AccountOverride, value: AccountState) {
    account_override.balance = value.balance;
    account_override.nonce = value.nonce.map(U64::from);
    account_override.code = value.code;
    for (key, value) in value.storage {
        if let Some(ref mut state) = account_override.state_diff {
            state.insert(key, value);
        } else {
            account_override.state_diff = Some(HashMap::from_iter(vec![(key, value)]));
        }
    }
}
