#![allow(missing_docs)]
#![allow(unused_variables)]
#![allow(missing_debug_implementations)]

use std::{collections::HashMap, time::Duration};

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, U256, U64};
use alloy_transport::TransportError;
use futures::{stream::FuturesOrdered, StreamExt};

use crate::{client::rpc::RpcClient, primitives::AccountState};

use super::execution::StateUpdate;

/// Maximum retries for RPC requests.
const MAX_RETRIES: u32 = 8;

/// The retry backoff in milliseconds.
const RETRY_BACKOFF_MS: u64 = 200;

/// A trait for fetching state updates.
#[async_trait::async_trait]
pub trait StateFetcher {
    async fn get_state_update(
        &self,
        addresses: Vec<&Address>,
        head: Option<u64>,
    ) -> Result<StateUpdate, TransportError>;

    async fn get_head(&self) -> Result<u64, TransportError>;

    async fn get_basefee(&self, block_number: Option<u64>) -> Result<u128, TransportError>;

    async fn get_account_state(
        &self,
        address: &Address,
        block_number: Option<u64>,
    ) -> Result<AccountState, TransportError>;
}

/// A basic state fetcher that uses an RPC client to fetch state updates.
#[derive(Clone, Debug)]
pub struct StateClient {
    client: RpcClient,
    retry_backoff: Duration,
}

impl StateClient {
    /// Create a new `StateClient` with the given URL and maximum retries.
    pub fn new(url: &str) -> Self {
        let client = RpcClient::new(url);
        Self {
            client,
            retry_backoff: Duration::from_millis(RETRY_BACKOFF_MS),
        }
    }
}

/// Get state updates for the specified block number or latest block if not provided.
#[async_trait::async_trait]
impl StateFetcher for StateClient {
    async fn get_state_update(
        &self,
        addresses: Vec<&Address>,
        block_number: Option<u64>,
    ) -> Result<StateUpdate, TransportError> {
        // Create a new batch
        let mut batch = self.client.new_batch();

        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        let mut account_states = HashMap::with_capacity(addresses.len());

        let mut nonce_futs = FuturesOrdered::new();
        let mut balance_futs = FuturesOrdered::new();

        let block_number = if let Some(block_number) = block_number {
            block_number
        } else {
            self.client.get_head().await?
        };

        // TODO: add block number in params
        for addr in &addresses {
            // We can use expect here since the only error is related to invalid parameters
            let nonce = batch
                .add_call("eth_getTransactionCount", &(addr, tag))
                .expect("Invalid parameters");
            let balance = batch
                .add_call("eth_getBalance", &(addr, tag))
                .expect("Invalid parameters");

            // Push the futures onto ordered list
            nonce_futs.push_back(nonce);
            balance_futs.push_back(balance);
        }

        // Make sure to send the batch!

        // After the batch is complete, we can get the results.
        // Note that requests may error separately!
        batch.send().await?;

        let basefee = self.client.get_basefee(None);

        // Collect the results
        let (nonce_vec, balance_vec, basefee) = tokio::join!(
            nonce_futs.collect::<Vec<_>>(),
            balance_futs.collect::<Vec<_>>(),
            basefee,
        );

        // Insert the results
        for (addr, nonce) in addresses.iter().zip(nonce_vec) {
            let nonce: U64 = nonce?;

            account_states
                .entry(**addr)
                .and_modify(|s: &mut AccountState| {
                    s.transaction_count = nonce.to();
                })
                .or_insert(AccountState {
                    transaction_count: nonce.to(),
                    balance: U256::ZERO,
                });
        }

        for (addr, balance) in addresses.iter().zip(balance_vec) {
            let balance = balance?;

            account_states
                .entry(**addr)
                .and_modify(|s: &mut AccountState| {
                    s.balance = balance;
                })
                .or_insert(AccountState {
                    transaction_count: 0,
                    balance,
                });
        }

        Ok(StateUpdate {
            account_states,
            min_basefee: basefee?,
            block_number,
        })
    }

    async fn get_head(&self) -> Result<u64, TransportError> {
        self.client.get_head().await
    }

    async fn get_basefee(&self, block_number: Option<u64>) -> Result<u128, TransportError> {
        self.client.get_basefee(block_number).await
    }

    async fn get_account_state(
        &self,
        address: &Address,
        block_number: Option<u64>,
    ) -> Result<AccountState, TransportError> {
        let mut retries = 0;

        loop {
            match self.client.get_account_state(address, block_number).await {
                Ok(state) => return Ok(state),
                Err(e) => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        return Err(e);
                    }

                    tracing::error!(error = ?e, "Error getting account state, retrying...");
                    tokio::time::sleep(self.retry_backoff).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::launch_anvil;

    #[tokio::test]
    async fn test_state_client() {
        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint());

        let address = anvil.addresses().first().unwrap();
        let state = client.get_account_state(address, None).await.unwrap();
        assert_eq!(state.balance, U256::from(10000000000000000000000u128));
        assert_eq!(state.transaction_count, 0);

        let head = client.get_head().await.unwrap();
        assert_eq!(head, 0);

        let basefee = client.get_basefee(None).await.unwrap();
        assert_eq!(basefee, 1_000_000_000);
    }
}
