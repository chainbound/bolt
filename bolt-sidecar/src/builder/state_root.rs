//! State root builder, responsible for constructing a new block's state_root
//! from a series of transaction traces and storage proofs.

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use alloy_primitives::{keccak256, B256, U256};
    use partial_mpt::StateTrie;
    use reqwest::Url;

    use crate::{
        builder::CallTraceManager, client::rpc::RpcClient, test_util::try_get_execution_api_url,
    };

    #[ignore]
    #[tokio::test]
    async fn test_trace_call() -> eyre::Result<()> {
        dotenvy::dotenv().ok();
        let _ = tracing_subscriber::fmt::try_init();

        let Some(rpc_url) = try_get_execution_api_url().await else {
            tracing::warn!("EL_RPC not reachable, skipping test");
            return Ok(());
        };

        tracing::info!("Starting test_trace_call");

        let rpc_url = Url::parse(rpc_url).unwrap();
        let client = RpcClient::new(rpc_url.clone());

        let (call_trace_manager, call_trace_handler) = CallTraceManager::new(rpc_url);
        tokio::spawn(call_trace_manager);

        // https://etherscan.io/block/20125606
        let block_number = 20125606;

        let latest_block = client.get_block(Some(block_number), true).await?;
        let latest_state_root = B256::from(latest_block.header.state_root.0);

        let mut state_trie = StateTrie::from_root(latest_state_root);

        let tx_requests = latest_block
            .transactions
            .as_transactions()
            .unwrap()
            .iter()
            .map(|tx| tx.clone().into_request())
            .collect::<Vec<_>>();

        for tx in tx_requests.iter() {
            call_trace_handler.add_trace(tx.clone(), block_number).await;
        }

        let diffs = call_trace_handler
            .fetch_accumulated_diffs(block_number)
            .await
            .unwrap();

        println!("Touched accounts: {:?}", diffs.keys().len());

        // load the touched account proofs in the trie
        let start = std::time::Instant::now();
        for account in diffs.keys().collect::<HashSet<_>>().clone() {
            let proof = client
                .get_proof(*account, vec![], Some(block_number))
                .await?;
            state_trie.load_proof(proof).unwrap();
        }

        println!(
            "Loaded proofs for {} accounts in {:?}",
            diffs.keys().collect::<HashSet<_>>().len(),
            start.elapsed()
        );

        // now apply state diffs to the trie
        for (address, diff) in diffs.iter() {
            if let Some(balance) = diff.balance {
                state_trie
                    .account_trie
                    .set_balance(*address, balance)
                    .unwrap();
            }
            if let Some(nonce) = diff.nonce {
                state_trie
                    .account_trie
                    .set_nonce(*address, U256::from(nonce))
                    .unwrap();
            }
            if let Some(code) = diff.code.clone() {
                state_trie
                    .account_trie
                    .set_code_hash(*address, keccak256(code))
                    .unwrap();
            }
            if let Some(ref state_diff) = diff.state_diff {
                for (key, value) in state_diff.iter() {
                    state_trie
                        .set_storage_value(
                            *address,
                            U256::from_be_bytes(key.0),
                            U256::from_be_bytes(value.0),
                        )
                        .unwrap();
                }
            }
        }

        // now we can get the new state root
        let new_state_root = state_trie.root().unwrap();
        println!("New state root: {:x}", new_state_root);

        let next_block = client.get_block(Some(block_number + 1), false).await?;
        assert_eq!(next_block.header.state_root, new_state_root);

        Ok(())
    }
}
