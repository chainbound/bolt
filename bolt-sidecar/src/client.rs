use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use alloy::ClientBuilder;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, U64};
use alloy_rpc_client as alloy;
use alloy_rpc_types::{AccountInfo, FeeHistory};
use alloy_transport::TransportResult;
use alloy_transport_http::Http;
use reqwest::{Client, Url};

use crate::types::AccountState;

/// An HTTP-based JSON-RPC client that supports batching. Implements all methods that are relevant
/// to Bolt state.
pub struct RpcClient(alloy::RpcClient<Http<Client>>);

impl RpcClient {
    pub fn new(url: &str) -> Self {
        let url = Url::from_str(url).unwrap();

        let client = ClientBuilder::default().http(url);

        Self(client)
    }

    /// Get the basefee of the latest block.
    pub async fn get_basefee(&self) -> TransportResult<u128> {
        let fee_history: FeeHistory = self
            .0
            .request(
                "eth_feeHistory",
                (U64::from(1), BlockNumberOrTag::Latest, &[] as &[f64]),
            )
            .await?;

        println!("{:?}", fee_history);

        Ok(fee_history.latest_block_base_fee().unwrap())
    }

    /// Get the latest block number
    pub async fn get_head(&self) -> TransportResult<u64> {
        self.0.request("eth_blockNumber", ()).await
    }

    /// Gets the latest account state for the given address
    pub async fn get_account_state(&self, address: &Address) -> TransportResult<AccountState> {
        let mut batch = self.0.new_batch();

        let balance = batch
            .add_call("eth_getBalance", &(address, BlockNumberOrTag::Latest))
            .expect("Correct parameters");

        let nonce = batch
            .add_call("eth_getNonce", &(address, BlockNumberOrTag::Latest))
            .expect("Correct parameters");

        // After the batch is complete, we can get the results.
        // Note that requests may error separately!
        batch.send().await?;

        Ok(AccountState {
            balance: balance.await.unwrap(),
            nonce: nonce.await.unwrap(),
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
    use alloy_node_bindings::Anvil;

    use super::*;

    #[tokio::test]
    async fn test_rpc_client() {
        let anvil = Anvil::new()
            .block_time(1)
            .chain_id(1337)
            .try_spawn()
            .expect("Anvil not found");

        let client = RpcClient::new(&anvil.endpoint());

        client.get_basefee().await.unwrap();
    }
}
