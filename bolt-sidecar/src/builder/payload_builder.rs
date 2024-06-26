#![allow(missing_docs)]

use super::compat::{to_alloy_execution_payload, to_reth_withdrawal};
use alloy_eips::{calc_excess_blob_gas, calc_next_block_base_fee, eip1559::BaseFeeParams};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types::Block;
use alloy_rpc_types_engine::ExecutionPayload as AlloyExecutionPayload;
use beacon_api_client::{BlockId, StateId};
use hex::FromHex;
use regex::Regex;
use reth_primitives::{
    constants::BEACON_NONCE, proofs, BlockBody, Bloom, Header, SealedBlock, SealedHeader,
    TransactionSigned, Withdrawals, EMPTY_OMMER_ROOT_HASH,
};
use reth_rpc_layer::{secret_to_bearer_header, JwtSecret};
use serde_json::Value;

use crate::RpcClient;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum PayloadBuilderError {
    #[error("Failed to parse from integer: {0}")]
    Parse(#[from] std::num::ParseIntError),
    #[error("Failed to de/serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Failed to decode hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Invalid JWT: {0}")]
    Jwt(#[from] reth_rpc_layer::JwtError),
    #[error("Failed HTTP request: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed while fetching from RPC: {0}")]
    Transport(#[from] alloy_transport::TransportError),
    #[error("Failed to build payload: {0}")]
    Custom(String),
}

#[derive(Debug)]
pub struct FallbackPayloadBuilder {
    fee_recipient: Address,
    extra_data: Bytes,
    execution_rpc_client: RpcClient,

    // Engine API error hinter
    engine_hinter: EngineHinter,
}

impl FallbackPayloadBuilder {
    pub fn new(
        fee_recipient: Address,
        jwt_hex: &str,
        engine_rpc_url: &str,
        execution_rpc_url: &str,
    ) -> Self {
        Self {
            fee_recipient,
            engine_hinter: EngineHinter {
                client: reqwest::Client::new(),
                jwt_hex: jwt_hex.to_string(),
                engine_rpc_url: engine_rpc_url.to_string(),
            },
            extra_data: hex::encode("Selfbuilt w Bolt").into(),
            execution_rpc_client: RpcClient::new(execution_rpc_url),
        }
    }
}

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
pub struct Hints {
    pub gas_used: Option<u64>,
    pub receipts_root: Option<B256>,
    pub logs_bloom: Option<Bloom>,
    pub blob_gas_used: Option<u64>,
    pub state_root: Option<B256>,
    pub block_hash: Option<B256>,
}

impl FallbackPayloadBuilder {
    /// Build a minimal payload to be used as a fallback
    pub async fn build_fallback_payload(
        &self,
        transactions: Vec<TransactionSigned>,
    ) -> Result<(SealedBlock, SealedHeader), PayloadBuilderError> {
        let latest_block = self.execution_rpc_client.get_block(None, true).await?;

        // TODO: refactor this once ConsensusState (https://github.com/chainbound/bolt/issues/58) is ready
        let beacon_api_endpoint = reqwest::Url::parse("http://remotebeast:3500").unwrap();
        let beacon_api = beacon_api_client::mainnet::Client::new(beacon_api_endpoint);

        let withdrawals = beacon_api
            .get_expected_withdrawals(StateId::Head, None)
            .await
            .unwrap()
            .into_iter()
            .map(to_reth_withdrawal)
            .collect::<Vec<_>>();

        let withdrawals = if withdrawals.is_empty() {
            None
        } else {
            Some(withdrawals)
        };

        // NOTE: for some reason, this call fails with an ApiResult deserialization error
        // when using the beacon_api_client crate directly, so we use reqwest temporarily.
        // this is to be refactored.
        let prev_randao = reqwest::Client::new()
            .get("http://remotebeast:3500/eth/v1/beacon/states/head/randao")
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

        let parent_beacon_block_root = beacon_api
            .get_beacon_block_root(BlockId::Head)
            .await
            .unwrap();

        let versioned_hashes = transactions
            .iter()
            .flat_map(|tx| tx.blob_versioned_hashes())
            .flatten()
            .collect::<Vec<_>>();

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
        let max_iterations = 5;
        let mut i = 1;
        let (sealed_header, sealed_block) = loop {
            let header = build_header_with_hints_and_context(&latest_block, &hints, &ctx);

            let sealed_header = header.clone().seal_slow();
            let sealed_block = SealedBlock::new(sealed_header.clone(), body.clone());

            let hinted_hash = hints.block_hash.unwrap_or(sealed_block.hash());
            let exec_payload = to_alloy_execution_payload(&sealed_block, hinted_hash);

            let engine_hint = self
                .engine_hinter
                .fetch_next_payload_hint(&exec_payload, &versioned_hashes, parent_beacon_block_root)
                .await?;

            match engine_hint {
                EngineApiHint::BlockHash(hash) => hints.block_hash = Some(hash),
                EngineApiHint::GasUsed(gas) => hints.gas_used = Some(gas),
                EngineApiHint::StateRoot(hash) => hints.state_root = Some(hash),
                EngineApiHint::ReceiptsRoot(hash) => hints.receipts_root = Some(hash),
                EngineApiHint::LogsBloom(bloom) => hints.logs_bloom = Some(bloom),

                EngineApiHint::ValidPayload => break (sealed_header, sealed_block),
            }

            if i > max_iterations {
                return Err(PayloadBuilderError::Custom(
                    "Failed to fetch all missing header values from geth error messages"
                        .to_string(),
                ));
            }

            i += 1;
        };

        Ok((sealed_block, sealed_header))
    }
}

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

#[derive(Debug)]
pub(crate) struct EngineHinter {
    client: reqwest::Client,
    jwt_hex: String,
    engine_rpc_url: String,
}

impl EngineHinter {
    pub async fn fetch_next_payload_hint(
        &self,
        exec_payload: &AlloyExecutionPayload,
        versioned_hashes: &[B256],
        parent_beacon_root: B256,
    ) -> Result<EngineApiHint, PayloadBuilderError> {
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
            if raw_hint.contains("\"status\":\"VALID\"") {
                return Ok(EngineApiHint::ValidPayload);
            } else {
                return Err(PayloadBuilderError::Custom(
                    "Failed to parse hint from engine response".to_string(),
                ));
            }
        };

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

        Err(PayloadBuilderError::Custom(
            "Failed to parse hint from engine response".to_string(),
        ))
    }
}

/// Reference: https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/core/block_validator.go#L122-L151,
/// https://github.com/ethereum/go-ethereum/blob/9298d2db884c4e3f9474880e3dcfd080ef9eacfa/beacon/engine/types.go#L253-L256
pub(crate) fn parse_geth_response(error: &str) -> Option<String> {
    let re = Regex::new(r"(?:local:|got) ([0-9a-zA-Z]+)").expect("valid regex");

    re.captures(error)
        .and_then(|capture| capture.get(1).map(|matched| matched.as_str().to_string()))
}

fn build_header_with_hints_and_context(
    latest_block: &Block,
    hints: &Hints,
    context: &Context,
) -> Header {
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
        // TODO: use slot time from beacon chain instead to account for reorgs
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
    use alloy_primitives::{hex, Address, U256};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::k256::ecdsa::SigningKey;
    use alloy_signer_local::PrivateKeySigner;
    use reth_primitives::TransactionSigned;

    use crate::builder::payload_builder::FallbackPayloadBuilder;

    #[tokio::test]
    async fn test_build_fallback_payload() -> eyre::Result<()> {
        dotenvy::dotenv().ok();

        let raw_sk = std::env::var("PRIVATE_KEY")?;
        let jwt = std::env::var("ENGINE_JWT")?;

        let execution = "http://remotebeast:8545";
        let engine = "http://remotebeast:8551";

        let builder = FallbackPayloadBuilder::new(Address::default(), &jwt, engine, execution);

        let sk = SigningKey::from_slice(hex::decode(raw_sk)?.as_slice())?;
        let signer = PrivateKeySigner::from_signing_key(sk.clone());
        let wallet = EthereumWallet::from(signer);

        let addy = Address::from_private_key(&sk);
        let tx = default_transaction(addy, 266);
        let tx_signed = tx.build(&wallet).await?;
        let raw_encoded = tx_signed.encoded_2718();
        let tx_signed_reth = TransactionSigned::decode_enveloped(&mut raw_encoded.as_slice())?;

        builder.build_fallback_payload(vec![tx_signed_reth]).await?;

        Ok(())
    }

    fn default_transaction(sender: Address, nonce: u64) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(sender)
            // Burn it
            .with_to(Address::ZERO)
            .with_chain_id(1)
            .with_nonce(nonce)
            .with_value(U256::from(100))
            .with_gas_limit(21_000)
            .with_max_priority_fee_per_gas(1_000_000_000)
            .with_max_fee_per_gas(20_000_000_000)
    }
}
