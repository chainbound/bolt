//! This module contains the `RpcClient` struct, which is a wrapper around the `alloy_rpc_client`.
//! It provides a simple interface to interact with the Execution layer JSON-RPC API.
use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use alloy::ClientBuilder;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, U256, U64};
use alloy_rpc_client as alloy;
use alloy_rpc_types::FeeHistory;
use alloy_transport::TransportResult;
use alloy_transport_http::Http;
use reqwest::{Client, Url};

use crate::types::AccountState;

/// An HTTP-based JSON-RPC client that supports batching. Implements all methods that are relevant
/// to Bolt state.
#[derive(Clone)]
pub struct RpcClient(alloy::RpcClient<Http<Client>>);

impl RpcClient {
    pub fn new(url: &str) -> Self {
        let url = Url::from_str(url).unwrap();

        let client = ClientBuilder::default().http(url);

        Self(client)
    }

    /// Get the basefee of the latest block.
    pub async fn get_basefee(&self, block_number: Option<u64>) -> TransportResult<u128> {
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        let fee_history: FeeHistory = self
            .0
            .request("eth_feeHistory", (U64::from(1), tag, &[] as &[f64]))
            .await?;

        Ok(fee_history.latest_block_base_fee().unwrap())
    }

    /// Get the latest block number
    pub async fn get_head(&self) -> TransportResult<u64> {
        let result: U64 = self.0.request("eth_blockNumber", ()).await?;

        Ok(result.to())
    }

    /// Gets the latest account state for the given address
    pub async fn get_account_state(
        &self,
        address: &Address,
        block_number: Option<u64>,
    ) -> TransportResult<AccountState> {
        let mut batch = self.0.new_batch();

        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        let balance = batch
            .add_call("eth_getBalance", &(address, tag))
            .expect("Correct parameters");

        let tx_count = batch
            .add_call(
                "eth_getTransactionCount",
                &(address, BlockNumberOrTag::Latest),
            )
            .expect("Correct parameters");

        // After the batch is complete, we can get the results.
        // Note that requests may error separately!
        batch.send().await?;

        let tx_count: U64 = tx_count.await?;
        let balance: U256 = balance.await?;

        Ok(AccountState {
            balance,
            transaction_count: tx_count.to(),
        })
    }
}

impl Deref for RpcClient {
    type Target = alloy::RpcClient<Http<Client>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RpcClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::constants::ETH_TO_WEI;
    use alloy_node_bindings::{Anvil, AnvilInstance};
    use alloy_primitives::{uint, Uint};

    use super::*;

    fn launch_anvil() -> AnvilInstance {
        Anvil::new().block_time(1).spawn()
    }

    #[tokio::test]
    async fn test_rpc_client() {
        let anvil = launch_anvil();
        let client = RpcClient::new(&anvil.endpoint());

        let addr = anvil.addresses().first().unwrap();

        let account_state = client.get_account_state(addr, None).await.unwrap();

        // Accounts in Anvil start with 10_000 ETH
        assert_eq!(
            account_state.balance,
            uint!(10_000U256 * Uint::from(ETH_TO_WEI))
        );

        assert_eq!(account_state.transaction_count, 0);
    }
}
