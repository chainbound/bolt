use std::{collections::HashMap, pin::Pin, task::Poll};

use alloy_eips::BlockId;
use alloy_primitives::{keccak256, Address, BlockNumber};
use alloy_rpc_types::TransactionRequest;
use alloy_rpc_types_trace::geth::{GethTrace, TraceResult};
use futures::{stream::FuturesOrdered, Future};
use tokio::sync::{mpsc, oneshot};

use crate::RpcClient;

// Steps:
// - Get previous block state root
// - Create partial MPT from state root
// - Simulate fallback block using trace_callMany RPC endpoint (or multiple debug_traceCall in Geth)
// - Get state diffs of touched accounts
// - Get account proofs for touched accounts (at the previous block) from local EL node, using eth_getProof
// - Load account proofs into partial MPT
// - Apply state diffs to partial MPT
// - Build new state root from partial MPT
// - Build new valid header with new state root
// - ?
// - Profit

// Components:
// 1. Add new methods to RpcClient: `eth_getProof`, `debug_traceCall`, `trace_callMany` -- DONE except `debug_traceCall`
// 2. Import, fork or re-implement an MPT library with "manual enough" access
// 3. Implement "state root calculator" using RpcClient and MPT library above

// async fn debug_trace_call_many(
//     &self,
//     bundles: Vec<Bundle>,
//     state_context: Option<StateContext>,
//     opts: Option<GethDebugTracingCallOptions>,
// ) -> RpcResult<Vec<Vec<GethTrace>>> {
//     let _permit = self.acquire_trace_permit().await;
//     Ok(Self::debug_trace_call_many(self, bundles, state_context, opts).await?)
// }

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use alloy_consensus::Account;
    use alloy_primitives::{keccak256, B256, U256};
    use alloy_rpc_types_trace::{
        geth::{
            GethDebugBuiltInTracerType, GethDebugTracerConfig, GethDebugTracerType,
            GethDebugTracingCallOptions, GethDebugTracingOptions, GethDefaultTracingOptions,
            GethTrace, PreStateConfig, PreStateFrame,
        },
        parity::{ChangedType, Delta, TraceType},
    };
    use partial_mpt::{AccountData, StateTrie};

    use crate::client::rpc::RpcClient;

    #[tokio::test]
    async fn test_trace_call() -> eyre::Result<()> {
        let client =
            RpcClient::new("https://nd-357-128-191.p2pify.com/31a0ef20aa969b0d191eb99065458caa");

        // https://etherscan.io/block/20125606
        let block_number = 20125606;

        let latest_block = client.get_block(Some(block_number), true).await?;
        let latest_state_root = B256::from(latest_block.header.state_root.0);

        let mut state_trie = StateTrie::from_root(latest_state_root);

        // let mut trace_types = HashSet::new();
        // trace_types.insert(TraceType::StateDiff);
        // trace_types.insert(TraceType::Trace);

        let mut debug_trace_call_responses = Vec::new();

        let mut geth_debug_tracing_options = GethDebugTracingOptions::default().with_tracer(
            GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::PreStateTracer),
        );
        geth_debug_tracing_options.config =
            GethDefaultTracingOptions::default().with_disable_storage(false);
        let geth_debug_tracing_call_options = GethDebugTracingCallOptions::default()
            .with_tracing_options(geth_debug_tracing_options.clone());

        let tx_requests = latest_block
            .transactions
            .as_transactions()
            .unwrap()
            .iter()
            .map(|tx| tx.clone().into_request())
            .collect::<Vec<_>>();

        for tx in tx_requests.iter() {
            let debug_trace_call_res = client
                .debug_trace_call(
                    tx.clone(),
                    Some(block_number),
                    Some(geth_debug_tracing_call_options.clone()),
                )
                .await?;
            debug_trace_call_responses.push(debug_trace_call_res);
        }

        for (i, res) in debug_trace_call_responses.iter().enumerate() {
            // println!("res[{}]: {:#?}", i, res);
            if let GethTrace::PreStateTracer(trace) = res {
                println!("trace[{}]: {:#?}", i, trace);
            }
            // println!("debug_trace_call_responses[{}]: {:#?}", i, res);
        }

        // get the list of touched accounts from the state diffs
        let touched_accounts = debug_trace_call_responses
            .iter()
            .map(|trace| match trace {
                GethTrace::PreStateTracer(PreStateFrame::Default(frame)) => {
                    frame.0.keys().cloned().collect::<Vec<_>>()
                }
                _ => vec![],
            })
            .flatten()
            .collect::<HashSet<_>>();

        println!("Touched accounts: {:?}", touched_accounts.len());

        // load the touched account proofs in the trie
        let start = std::time::Instant::now();
        for account in touched_accounts.clone() {
            let proof = client
                .get_proof(account, vec![], Some(block_number))
                .await?;
            state_trie.load_proof(proof).unwrap();
        }
        println!(
            "Loaded proofs for {} accounts in {:?}",
            touched_accounts.len(),
            start.elapsed()
        );

        // now apply state diffs to the trie
        for trace in debug_trace_call_responses.iter() {
            if let GethTrace::PreStateTracer(PreStateFrame::Default(frame)) = trace {
                frame.0.iter().for_each(|(address, account)| {
                    if let Some(balance) = account.balance {
                        state_trie
                            .account_trie
                            .set_balance(*address, balance)
                            .unwrap();
                    }
                    if let Some(nonce) = account.nonce {
                        state_trie
                            .account_trie
                            .set_nonce(*address, U256::from(nonce))
                            .unwrap();
                    }
                    if let Some(code) = account.code.clone() {
                        state_trie
                            .account_trie
                            .set_code_hash(*address, keccak256(code))
                            .unwrap();
                    }
                    for (key, value) in account.storage.iter() {
                        state_trie
                            .set_storage_value(
                                *address,
                                U256::from_be_bytes(key.0),
                                U256::from_be_bytes(value.0),
                            )
                            .unwrap();
                    }
                })
            } else {
                continue;
            }

            // for (address, diff) in trace.state_diff.unwrap().iter() {
            //     match diff.balance {
            //         Delta::Added(n) => {
            //             state_trie.account_trie.set_balance(*address, n).unwrap();
            //         }
            //         Delta::Changed(ChangedType { to, .. }) => {
            //             state_trie.account_trie.set_balance(*address, to).unwrap()
            //         }
            //         Delta::Removed(_) => {
            //             state_trie
            //                 .account_trie
            //                 .set_balance(*address, U256::ZERO)
            //                 .unwrap();
            //         }
            //         Delta::Unchanged => { /* do nothing */ }
            //     }
            //     match diff.nonce {
            //         Delta::Added(n) => {
            //             state_trie.account_trie.set_nonce(*address, n.to()).unwrap();
            //         }
            //         Delta::Changed(ChangedType { to, .. }) => {
            //             state_trie
            //                 .account_trie
            //                 .set_nonce(*address, to.to())
            //                 .unwrap();
            //         }
            //         Delta::Removed(_) => {
            //             state_trie
            //                 .account_trie
            //                 .set_nonce(*address, U256::ZERO)
            //                 .unwrap();
            //         }
            //         Delta::Unchanged => { /* do nothing */ }
            //     }
            //     match diff.nonce {
            //         Delta::Added(n) => {
            //             state_trie.account_trie.set_nonce(*address, n.to()).unwrap();
            //         }
            //         Delta::Changed(ChangedType { to, .. }) => {
            //             state_trie
            //                 .account_trie
            //                 .set_nonce(*address, to.to())
            //                 .unwrap();
            //         }
            //         Delta::Removed(_) => {
            //             state_trie
            //                 .account_trie
            //                 .set_nonce(*address, U256::ZERO)
            //                 .unwrap();
            //         }
            //         Delta::Unchanged => { /* do nothing */ }
            //     }

            //     // For each storage key-value pair
            //     for (key, value) in diff.storage.iter() {
            //         let key = U256::from_be_bytes(key.0);

            //         match value {
            //             Delta::Added(n) => {
            //                 state_trie
            //                     .set_storage_value(*address, key, U256::from_be_bytes(n.0))
            //                     .unwrap();
            //             }
            //             Delta::Changed(ChangedType { to, .. }) => {
            //                 state_trie
            //                     .set_storage_value(*address, key, U256::from_be_bytes(to.0))
            //                     .unwrap();
            //             }
            //             Delta::Removed(_) => {
            //                 state_trie
            //                     .set_storage_value(*address, key, U256::ZERO)
            //                     .unwrap();
            //             }
            //             Delta::Unchanged => { /* do nothing */ }
            //         }
            //     }
            // }
        }

        // now we can get the new state root
        let new_state_root = state_trie.root().unwrap();
        println!("New state root: {:x}", new_state_root);

        let next_block = client.get_block(Some(block_number + 1), false).await?;
        assert_eq!(next_block.header.state_root, new_state_root);

        Ok(())
    }
}
