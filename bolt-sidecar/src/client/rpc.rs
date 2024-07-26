//! This module contains the `RpcClient` struct, which is a wrapper around the `alloy_rpc_client`.
//! It provides a simple interface to interact with the Execution layer JSON-RPC API.

use futures::future::join_all;
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, Bytes, B256, U256, U64},
    rpc::{
        client::{self as alloyClient, ClientBuilder, Waiter},
        types::{
            trace::{
                geth::{GethDebugTracingCallOptions, GethTrace},
                parity::{TraceResults, TraceType},
            },
            {Block, EIP1186AccountProofResponse, FeeHistory, TransactionRequest},
        },
    },
    transports::{http::Http, TransportErrorKind, TransportResult},
};

use reqwest::{Client, Url};

use crate::primitives::AccountState;

/// An HTTP-based JSON-RPC client that supports batching.
/// Implements all methods that are relevant to Bolt state.
#[derive(Clone, Debug)]
pub struct RpcClient(alloyClient::RpcClient<Http<Client>>);

impl RpcClient {
    /// Create a new `RpcClient` with the given URL.
    pub fn new<U: Into<Url>>(url: U) -> Self {
        let client = ClientBuilder::default().http(url.into());

        Self(client)
    }

    /// Get the chain ID.
    pub async fn get_chain_id(&self) -> TransportResult<u64> {
        let chain_id: String = self.0.request("eth_chainId", ()).await?;
        let chain_id = chain_id
            .get(2..)
            .ok_or(TransportErrorKind::Custom("not hex prefixed result".into()))?;

        let decoded = u64::from_str_radix(chain_id, 16).map_err(|e| {
            TransportErrorKind::Custom(
                format!("could not decode {} into u64: {}", chain_id, e).into(),
            )
        })?;
        Ok(decoded)
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

    /// Get the blob basefee of the latest block.
    ///
    /// Reference: https://github.com/ethereum/execution-apis/blob/main/src/eth/fee_market.yaml
    pub async fn get_blob_basefee(&self, block_number: Option<u64>) -> TransportResult<u128> {
        let block_count = U64::from(1);
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);
        let reward_percentiles: Vec<f64> = vec![];
        let fee_history: FeeHistory = self
            .0
            .request("eth_feeHistory", (block_count, tag, &reward_percentiles))
            .await?;

        Ok(fee_history.latest_block_blob_base_fee().unwrap_or(0))
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
            .add_call("eth_getTransactionCount", &(address, tag))
            .expect("Correct parameters");

        let code = batch
            .add_call("eth_getCode", &(address, tag))
            .expect("Correct parameters");

        // After the batch is complete, we can get the results.
        // Note that requests may error separately!
        batch.send().await?;

        let tx_count: U64 = tx_count.await?;
        let balance: U256 = balance.await?;
        let code: Bytes = code.await?;

        Ok(AccountState {
            balance,
            transaction_count: tx_count.to(),
            has_code: !code.is_empty(),
        })
    }

    /// Get the block with the given number. If `None`, the latest block is returned.
    pub async fn get_block(&self, block_number: Option<u64>, full: bool) -> TransportResult<Block> {
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);

        self.0.request("eth_getBlockByNumber", (tag, full)).await
    }

    /// Returns the account and storage values of the specified account including the Merkle-proof.
    /// If the block number is `None`, the latest block is used.
    pub async fn get_proof(
        &self,
        address: Address,
        storage_keys: Vec<B256>,
        block_number: Option<u64>,
    ) -> TransportResult<EIP1186AccountProofResponse> {
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);
        let params = (address, storage_keys, tag);

        self.0.request("eth_getProof", params).await
    }

    /// Perform multiple `eth_getProof` calls in a single batch.
    pub async fn get_proof_batched(
        &self,
        opts: Vec<(Address, Vec<B256>, BlockNumberOrTag)>,
    ) -> TransportResult<Vec<EIP1186AccountProofResponse>> {
        let mut batch = self.0.new_batch();

        let mut proofs: Vec<Waiter<EIP1186AccountProofResponse>> = Vec::new();

        for params in opts {
            proofs.push(
                batch
                    .add_call("eth_getProof", &params)
                    .expect("Correct parameters"),
            );
        }

        batch.send().await?;

        // Important: join_all will preserve the order of the proofs
        join_all(proofs)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
    }

    /// Performs multiple call traces on top of the same block. i.e. transaction n will be executed
    /// on top of a pending block with all n-1 transactions applied (traced) first.
    ///
    /// Note: Allows tracing dependent transactions, hence all transactions are traced in sequence
    pub async fn trace_call_many(
        &self,
        calls: Vec<(TransactionRequest, HashSet<TraceType>)>,
        block_number: Option<u64>,
    ) -> TransportResult<Vec<TraceResults>> {
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);
        let params = (calls, tag);

        self.0.request("trace_callMany", params).await
    }

    /// Performs the `debug_traceCall` JSON-RPC method.
    pub async fn debug_trace_call(
        &self,
        tx: TransactionRequest,
        block_number: Option<u64>,
        opts: Option<GethDebugTracingCallOptions>,
    ) -> TransportResult<GethTrace> {
        let tag = block_number.map_or(BlockNumberOrTag::Latest, BlockNumberOrTag::Number);
        let params = (tx, tag, opts);

        self.0.request("debug_traceCall", params).await
    }

    /// Send a raw transaction to the network.
    pub async fn send_raw_transaction(&self, raw: Bytes) -> TransportResult<B256> {
        self.0.request("eth_sendRawTransaction", [raw]).await
    }
}

impl Deref for RpcClient {
    type Target = alloyClient::RpcClient<Http<Client>>;

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
    use std::str::FromStr;

    use alloy::{
        consensus::constants::ETH_TO_WEI,
        primitives::{uint, Uint},
    };
    use dotenvy::dotenv;

    use crate::test_util::launch_anvil;

    use super::*;

    #[tokio::test]
    async fn test_rpc_client() {
        let anvil = launch_anvil();
        let anvil_url = Url::from_str(&anvil.endpoint()).unwrap();
        let client = RpcClient::new(anvil_url);

        let addr = anvil.addresses().first().unwrap();

        let account_state = client.get_account_state(addr, None).await.unwrap();

        // Accounts in Anvil start with 10_000 ETH
        assert_eq!(
            account_state.balance,
            uint!(10_000U256 * Uint::from(ETH_TO_WEI))
        );

        assert_eq!(account_state.transaction_count, 0);
    }

    #[tokio::test]
    #[ignore]
    async fn test_smart_contract_code() -> eyre::Result<()> {
        dotenv().ok();
        let rpc_url = Url::parse(std::env::var("RPC_URL").unwrap().as_str())?;
        let rpc_client = RpcClient::new(rpc_url);

        // random deployed smart contract address
        let addr = Address::from_str("0xBA12222222228d8Ba445958a75a0704d566BF2C8")?;
        let account = rpc_client.get_account_state(&addr, None).await?;

        assert!(account.has_code);

        Ok(())
    }
}
