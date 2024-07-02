use alloy_eips::{calc_excess_blob_gas, calc_next_block_base_fee, eip1559::BaseFeeParams};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types::Block;
use alloy_rpc_types_engine::ExecutionPayload as AlloyExecutionPayload;
use beacon_api_client::{BlockId, StateId};
use hex::FromHex;
use regex::Regex;
use reth_primitives::{
    constants::BEACON_NONCE, proofs, BlockBody, Bloom, Header, SealedBlock, TransactionSigned,
    Withdrawals, EMPTY_OMMER_ROOT_HASH,
};
use reth_rpc_layer::{secret_to_bearer_header, JwtSecret};
use serde_json::Value;

use super::{
    compat::{to_alloy_execution_payload, to_reth_withdrawal},
    BuilderError,
};
use crate::RpcClient;

/// Extra-data payload field used for locally built blocks, decoded in UTF-8.
///
/// Corresponds to the string "Self-built with Bolt". It can be max 32 bytes
const DEFAULT_EXTRA_DATA: [u8; 20] = [
    0x53, 0x65, 0x6c, 0x66, 0x2d, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20,
    0x42, 0x6f, 0x6c, 0x74,
];

/// The fallback payload builder is responsible for assembling a valid
/// sealed block from a set of transactions. It (ab)uses the engine API
/// to fetch "hints" for missing header values, such as the block hash,
/// gas used, state root, etc.
///
/// The builder will keep querying the engine API until it has all the
/// necessary values to seal the block. This is a temporary solution
/// until the engine API is able to provide a full sealed block.
///
/// Find more information about this process & its reasoning here:
/// <https://github.com/chainbound/bolt/discussions/59>
#[derive(Debug)]
pub struct FallbackPayloadBuilder {
    extra_data: Bytes,
    fee_recipient: Address,
    beacon_api_url: String,
    execution_rpc_client: RpcClient,
    engine_hinter: EngineHinter,
}

impl FallbackPayloadBuilder {
    /// Create a new fallback payload builder
    pub fn new(
        jwt_hex: &str,
        fee_recipient: Address,
        engine_rpc_url: &str,
        execution_rpc_url: &str,
        beacon_api_url: &str,
    ) -> Self {
        let engine_hinter = EngineHinter {
            client: reqwest::Client::new(),
            jwt_hex: jwt_hex.to_string(),
            engine_rpc_url: engine_rpc_url.to_string(),
        };

        Self {
            fee_recipient,
            engine_hinter,
            beacon_api_url: beacon_api_url.to_string(),
            extra_data: DEFAULT_EXTRA_DATA.into(),
            execution_rpc_client: RpcClient::new(execution_rpc_url),
        }
    }
}

/// Lightweight context struct to hold the necessary values for
/// building a sealed block. Some of this data is fetched from the
/// beacon chain, while others are calculated locally or from the
/// transactions themselves.
#[derive(Debug, Default)]
pub struct Context {
    extra_data: Bytes,
    base_fee: u64,
    excess_blob_gas: u64,
    prev_randao: B256,
    fee_recipient: Address,
    transactions_root: B256,
    withdrawals_root: Option<B256>,
    parent_beacon_block_root: B256,
}

#[derive(Debug, Default)]
#[allow(missing_docs)]
pub struct Hints {
    pub gas_used: Option<u64>,
    pub receipts_root: Option<B256>,
    pub logs_bloom: Option<Bloom>,
    pub blob_gas_used: Option<u64>,
    pub state_root: Option<B256>,
    pub block_hash: Option<B256>,
}

impl FallbackPayloadBuilder {
    /// Build a minimal payload to be used as a fallback in case PBS relays fail
    /// to provide a valid payload that fulfills the commitments made by Bolt.
    pub async fn build_fallback_payload(
        &self,
        transactions: Vec<TransactionSigned>,
    ) -> Result<SealedBlock, BuilderError> {
        let latest_block = self.execution_rpc_client.get_block(None, true).await?;
        tracing::info!(num = ?latest_block.header.number, "got latest block");

        // TODO: refactor this once ConsensusState (https://github.com/chainbound/bolt/issues/58) is ready
        let beacon_api_endpoint = reqwest::Url::parse(&self.beacon_api_url).unwrap();
        let beacon_api = beacon_api_client::mainnet::Client::new(beacon_api_endpoint);

        let withdrawals = beacon_api
            .get_expected_withdrawals(StateId::Head, None)
            .await
            .unwrap()
            .into_iter()
            .map(to_reth_withdrawal)
            .collect::<Vec<_>>();
        tracing::info!(amount = ?withdrawals.len(), "got withdrawals");

        let withdrawals = if withdrawals.is_empty() {
            None
        } else {
            Some(withdrawals)
        };

        // NOTE: for some reason, this call fails with an ApiResult deserialization error
        // when using the beacon_api_client crate directly, so we use reqwest temporarily.
        // this is to be refactored.
        let prev_randao = reqwest::Client::new()
            .get(format!(
                "{}/eth/v1/beacon/states/head/randao",
                self.beacon_api_url
            ))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        let prev_randao = prev_randao
            .pointer("/data/randao")
            .unwrap()
            .as_str()
            .unwrap();
        let prev_randao = B256::from_hex(prev_randao).unwrap();
        tracing::info!("got prev_randao");

        let parent_beacon_block_root = beacon_api
            .get_beacon_block_root(BlockId::Head)
            .await
            .unwrap();
        tracing::info!(parent = ?parent_beacon_block_root, "got parent_beacon_block_root");

        let versioned_hashes = transactions
            .iter()
            .flat_map(|tx| tx.blob_versioned_hashes())
            .flatten()
            .collect::<Vec<_>>();
        tracing::info!(amount = ?versioned_hashes.len(), "got versioned_hashes");

        let base_fee = calc_next_block_base_fee(
            latest_block.header.gas_used,
            latest_block.header.gas_limit,
            latest_block.header.base_fee_per_gas.unwrap_or_default(),
            BaseFeeParams::ethereum(),
        ) as u64;

        let excess_blob_gas = calc_excess_blob_gas(
            latest_block.header.excess_blob_gas.unwrap_or_default(),
            latest_block.header.blob_gas_used.unwrap_or_default(),
        ) as u64;

        let ctx = Context {
            base_fee,
            excess_blob_gas,
            parent_beacon_block_root,
            prev_randao,
            extra_data: self.extra_data.clone(),
            fee_recipient: self.fee_recipient,
            transactions_root: proofs::calculate_transaction_root(&transactions),
            withdrawals_root: withdrawals
                .as_ref()
                .map(|w| proofs::calculate_withdrawals_root(w)),
        };

        let body = BlockBody {
            transactions,
            ommers: Vec::new(),
            withdrawals: withdrawals.map(Withdrawals::new),
        };

        let mut hints = Hints::default();
        let max_iterations = 20;
        let mut i = 0;
        loop {
            let header = build_header_with_hints_and_context(&latest_block, &hints, &ctx);

            let sealed_header = header.seal_slow();
            let sealed_block = SealedBlock::new(sealed_header.clone(), body.clone());

            let block_hash = hints.block_hash.unwrap_or(sealed_block.hash());

            let exec_payload = to_alloy_execution_payload(&sealed_block, block_hash);

            let engine_hint = self
                .engine_hinter
                .fetch_next_payload_hint(&exec_payload, &versioned_hashes, parent_beacon_block_root)
                .await?;

            tracing::info!("engine_hint: {:?}", engine_hint);

            match engine_hint {
                EngineApiHint::BlockHash(hash) => {
                    tracing::warn!("Should not receive block hash hint {:?}", hash);
                    hints.block_hash = Some(hash)
                }

                EngineApiHint::GasUsed(gas) => {
                    hints.gas_used = Some(gas);
                    hints.block_hash = None;
                }
                EngineApiHint::StateRoot(hash) => {
                    hints.state_root = Some(hash);
                    hints.block_hash = None
                }
                EngineApiHint::ReceiptsRoot(hash) => {
                    hints.receipts_root = Some(hash);
                    hints.block_hash = None
                }
                EngineApiHint::LogsBloom(bloom) => {
                    hints.logs_bloom = Some(bloom);
                    hints.block_hash = None
                }

                EngineApiHint::ValidPayload => return Ok(sealed_block),
            }

            if i > max_iterations {
                return Err(BuilderError::Custom(
                    "Too many iterations: Failed to fetch all missing header values from geth error messages"
                        .to_string(),
                ));
            }

            i += 1;
        }
    }
}

/// Engine API hint values that can be fetched from the engine API
/// to complete the sealed block. These hints are used to fill in
/// missing values in the block header.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum EngineApiHint {
    BlockHash(B256),
    GasUsed(u64),
    StateRoot(B256),
    ReceiptsRoot(B256),
    LogsBloom(Bloom),
    ValidPayload,
}

/// Engine hinter struct that is responsible for fetching hints from the
/// engine API to complete the sealed block. This struct is used by the
/// fallback payload builder to fetch missing header values.
#[derive(Debug)]
pub(crate) struct EngineHinter {
    client: reqwest::Client,
    jwt_hex: String,
    engine_rpc_url: String,
}

impl EngineHinter {
    /// Fetch the next payload hint from the engine API to complete the sealed block.
    pub async fn fetch_next_payload_hint(
        &self,
        exec_payload: &AlloyExecutionPayload,
        versioned_hashes: &[B256],
        parent_beacon_root: B256,
    ) -> Result<EngineApiHint, BuilderError> {
        tracing::info!("jwt_hex: {:?}", self.jwt_hex);

        let auth_jwt = secret_to_bearer_header(&JwtSecret::from_hex(&self.jwt_hex)?);

        let body = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"engine_newPayloadV3","params":[{}, {}, "{:?}"]}}"#,
            serde_json::to_string(&exec_payload)?,
            serde_json::to_string(&versioned_hashes)?,
            parent_beacon_root
        );

        let raw_hint = self
            .client
            .post(&self.engine_rpc_url)
            .header("Content-Type", "application/json")
            .header("Authorization", auth_jwt.clone())
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        let Some(hint_value) = parse_geth_response(&raw_hint) else {
            // If the hint is not found, it means that we likely got a VALID
            // payload response or an error message that we can't parse.
            if raw_hint.contains("\"status\":\"VALID\"") {
                return Ok(EngineApiHint::ValidPayload);
            } else {
                return Err(BuilderError::InvalidEngineHint(raw_hint));
            }
        };

        tracing::info!("raw hint: {:?}", raw_hint);

        // Match the hint value to the corresponding header field and return it
        if raw_hint.contains("blockhash mismatch") {
            return Ok(EngineApiHint::BlockHash(B256::from_hex(hint_value)?));
        } else if raw_hint.contains("invalid gas used") {
            return Ok(EngineApiHint::GasUsed(hint_value.parse()?));
        } else if raw_hint.contains("invalid merkle root") {
            return Ok(EngineApiHint::StateRoot(B256::from_hex(hint_value)?));
        } else if raw_hint.contains("invalid receipt root hash") {
            return Ok(EngineApiHint::ReceiptsRoot(B256::from_hex(hint_value)?));
        } else if raw_hint.contains("invalid bloom") {
            return Ok(EngineApiHint::LogsBloom(Bloom::from_hex(&hint_value)?));
        };

        Err(BuilderError::Custom(
            "Unexpected: failed to parse any hint from engine response".to_string(),
        ))
    }
}

/// Parse the hint value from the engine response.
/// An example error message from the engine API looks like this:
/// ```text
/// {"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"local: blockhash mismatch: got 0x... expected 0x..."}}
/// ```
///
/// Geth Reference:
/// - [ValidateState](<https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/core/block_validator.go#L122-L151>)
/// - [Blockhash Mismatch](<https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/beacon/engine/types.go#L253-L256>)
pub(crate) fn parse_geth_response(error: &str) -> Option<String> {
    // Capture either the "local" or "got" value from the error message
    let re = Regex::new(r"(?:local:|got) ([0-9a-zA-Z]+)").expect("valid regex");

    re.captures(error)
        .and_then(|capture| capture.get(1).map(|matched| matched.as_str().to_string()))
}

/// Build a header with the given hints and context values.
pub(crate) fn build_header_with_hints_and_context(
    latest_block: &Block,
    hints: &Hints,
    context: &Context,
) -> Header {
    // Use the available hints, or default to an empty value if not present.
    let gas_used = hints.gas_used.unwrap_or_default();
    let receipts_root = hints.receipts_root.unwrap_or_default();
    let logs_bloom = hints.logs_bloom.unwrap_or_default();
    let blob_gas_used = hints.blob_gas_used.unwrap_or_default();
    let state_root = hints.state_root.unwrap_or_default();

    Header {
        parent_hash: latest_block.header.hash.unwrap_or_default(),
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: context.fee_recipient,
        state_root,
        transactions_root: context.transactions_root,
        receipts_root,
        withdrawals_root: context.withdrawals_root,
        logs_bloom,
        difficulty: U256::ZERO,
        number: latest_block.header.number.unwrap_or_default() + 1,
        gas_limit: latest_block.header.gas_limit as u64,
        gas_used,
        // TODO: use slot time from beacon chain instead, to account for reorgs
        timestamp: latest_block.header.timestamp + 12,
        mix_hash: context.prev_randao,
        nonce: BEACON_NONCE,
        base_fee_per_gas: Some(context.base_fee),
        blob_gas_used: Some(blob_gas_used),
        excess_blob_gas: Some(context.excess_blob_gas),
        parent_beacon_block_root: Some(context.parent_beacon_block_root),
        extra_data: context.extra_data.clone(),
    }
}

#[cfg(test)]
mod tests {
    use alloy_eips::eip2718::Encodable2718;
    use alloy_network::{EthereumWallet, TransactionBuilder};
    use alloy_primitives::{hex, Address};
    use alloy_signer::k256::ecdsa::SigningKey;
    use alloy_signer_local::PrivateKeySigner;
    use reth_primitives::TransactionSigned;

    use crate::{
        builder::payload_builder::FallbackPayloadBuilder,
        test_util::{
            default_test_transaction, try_get_beacon_api_url, try_get_engine_api_url,
            try_get_execution_api_url,
        },
    };

    #[tokio::test]
    async fn test_build_fallback_payload() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();
        dotenvy::dotenv().ok();

        let raw_sk = std::env::var("PRIVATE_KEY")?;
        let jwt = std::env::var("ENGINE_JWT")?;

        let Some(execution) = try_get_execution_api_url().await else {
            tracing::warn!("skipping test: execution API URL is not reachable");
            return Ok(());
        };
        let Some(engine) = try_get_engine_api_url().await else {
            tracing::warn!("skipping test: engine API URL is not reachable");
            return Ok(());
        };
        let Some(beacon) = try_get_beacon_api_url().await else {
            tracing::warn!("skipping test: beacon API URL is not reachable");
            return Ok(());
        };

        let builder =
            FallbackPayloadBuilder::new(&jwt, Address::default(), engine, execution, beacon);

        let sk = SigningKey::from_slice(hex::decode(raw_sk)?.as_slice())?;
        let signer = PrivateKeySigner::from_signing_key(sk.clone());
        let wallet = EthereumWallet::from(signer);

        let addy = Address::from_private_key(&sk);
        let tx = default_test_transaction(addy, Some(1)).with_chain_id(1);
        let tx_signed = tx.build(&wallet).await?;
        let raw_encoded = tx_signed.encoded_2718();
        let tx_signed_reth = TransactionSigned::decode_enveloped(&mut raw_encoded.as_slice())?;

        let block = builder.build_fallback_payload(vec![tx_signed_reth]).await?;
        assert_eq!(block.body.len(), 1);

        Ok(())
    }
}
