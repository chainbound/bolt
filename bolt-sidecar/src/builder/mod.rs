#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(unused_imports)]

pub mod template;
pub use template::BlockTemplate;

pub mod payload_builder;
pub mod state_root;

use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    task::Poll,
};

use alloy_eips::BlockId;
use alloy_primitives::{Address, BlockNumber};
use alloy_rpc_types::TransactionRequest;
use alloy_rpc_types_trace::geth::{GethTrace, TraceResult};
use alloy_transport::TransportResult;
use futures::{stream::FuturesOrdered, Future};
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
        res: oneshot::Sender<Option<HashMap<Address, GethTrace>>>,
    },
}

#[derive(Debug)]
pub struct CallTraceManager {
    rpc: RpcClient,
    trace_rx: mpsc::Receiver<TraceCommand>,
    trace_request_queue: VecDeque<TransactionRequest>,
    pending_traces: HashMap<BlockNumber, FuturesOrdered<TraceFuture>>,
    accumulated_state_diffs: HashMap<BlockNumber, HashMap<Address, GethTrace>>,
}

type TraceFuture = JoinHandle<TransportResult<GethTrace>>;

impl CallTraceManager {
    /// Creates a new [CallTraceManager] instance, which will listen for incoming
    /// trace requests and process them in the background using the given RPC client.
    pub fn new(url: &str) -> (Self, mpsc::Sender<TraceCommand>) {
        let rpc = RpcClient::new(url);
        let (tx, rx) = mpsc::channel(100);

        (
            Self {
                rpc,
                trace_rx: rx,
                trace_request_queue: Default::default(),
                pending_traces: Default::default(),
                accumulated_state_diffs: Default::default(),
            },
            tx,
        )
    }

    /// Runs the [CallTraceManager] actor, processing incoming trace requests and
    /// accumulating the resulting state diffs for each block in the background.
    pub async fn run(mut self) {
        while let Some(request) = self.trace_rx.recv().await {
            match request {
                TraceCommand::AddTrace { transaction, block } => {
                    let rpc = self.rpc.clone();
                    let pending_task = tokio::spawn(async move {
                        // TODO: add opts to the trace call
                        rpc.debug_trace_call(transaction, Some(block), None).await
                    });

                    let pending_traces_for_block = self.pending_traces.entry(block).or_default();
                    pending_traces_for_block.push_back(pending_task);
                }
                TraceCommand::FetchAccumulatedDiffs { block, res } => {
                    // check if there are pending requests for this block
                    if let Some(pending) = self.pending_traces.get(&block) {
                        // There is more work to do, so we can't send the result yet
                        // TODO: wait until all pending tasks are done in the background and then send the result
                        if !pending.is_empty() {
                            let _ = res.send(None);
                            continue;
                        }
                    }

                    let _ = res.send(self.accumulated_state_diffs.remove(&block));
                }
            }
        }
    }
}
