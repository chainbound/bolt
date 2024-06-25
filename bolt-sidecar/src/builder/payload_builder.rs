#![allow(missing_docs)]
#![allow(unused)]

use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, Bytes, B256, U256};
use ethereum_consensus::{
    capella::spec,
    crypto::bls::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey},
    deneb::mainnet::ExecutionPayloadHeader,
    ssz::prelude::{ssz_rs, ByteList, ByteVector, List},
    types::mainnet::ExecutionPayload,
};
use reth_primitives::{
    constants::BEACON_NONCE, proofs, BlockBody, Bloom, Header, SealedBlock, SealedHeader,
    TransactionSigned, Withdrawals, EMPTY_OMMER_ROOT_HASH,
};

use crate::primitives::{BuilderBid, Slot};

#[derive(Debug, thiserror::Error)]
pub enum PayloadBuilderError {
    #[error("Failed to build payload: {0}")]
    Custom(String),
}

#[derive(Debug)]
pub struct FallbackPayloadBuilder {
    fee_recipient: Address,

    // keypair used for signing the payload
    private_key: BlsSecretKey,
    public_key: BlsPublicKey,
}

/// Minimal execution context required to build a valid payload on the target slot.
#[derive(Debug, Default)]
pub struct ExecutionContext {
    head_slot_number: Slot,
    parent_hash: B256,
    parent_beacon_block_root: B256,
    transactions: Vec<TransactionSigned>,
    block: NextBlockInfo,
    excess_blob_gas: u64,
}

#[derive(Debug, Default)]
pub struct NextBlockInfo {
    number: u64,
    timestamp: u64,
    prev_randao: B256,
    base_fee: u64,
    extra_data: Bytes,
    gas_limit: u64,
}

#[derive(Debug)]
pub struct Hints {
    pub gas_used: Option<u64>,
    pub receipts_root: Option<B256>,
    pub withdrawals_root: Option<B256>,
    pub logs_bloom: Option<Bloom>,
    pub blob_gas_used: Option<u64>,
    pub state_root: Option<B256>,
}

impl FallbackPayloadBuilder {
    /// Build a minimal payload to be used as a fallback
    pub async fn build_fallback_payload(
        &self,
        context: ExecutionContext,
        hints: Hints,
    ) -> Result<SealedBlock, PayloadBuilderError> {
        let transactions_root = proofs::calculate_transaction_root(&context.transactions);

        // TODO: actually get the state root (needs to count post-state diffs)
        let state_root = hints.state_root.unwrap_or_default();

        // TODO: fill somehow
        let withdrawals_root = hints.withdrawals_root;
        let receipts_root = hints.receipts_root.unwrap_or_default();
        let logs_bloom = hints.logs_bloom.unwrap_or_default();
        let gas_used = hints.gas_used.unwrap_or_default();

        // TODO: this should be fine (remove min-bid requirement)
        let value = U256::ZERO;

        let header = Header {
            parent_hash: context.parent_hash,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: self.fee_recipient,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            difficulty: U256::ZERO,
            number: context.block.number,
            gas_limit: context.block.gas_limit,
            gas_used,
            timestamp: context.block.timestamp,
            mix_hash: context.block.prev_randao,
            nonce: BEACON_NONCE,
            base_fee_per_gas: Some(context.block.base_fee),
            blob_gas_used: hints.blob_gas_used,
            excess_blob_gas: Some(context.excess_blob_gas),
            parent_beacon_block_root: Some(context.parent_beacon_block_root),
            extra_data: context.block.extra_data,
        };

        let body = BlockBody {
            transactions: context.transactions,
            ommers: Vec::new(),
            withdrawals: None,
        };

        let sealed_block = SealedBlock::new(header.seal_slow(), body);

        // TODO: transform into submission later
        // let submission = BuilderBid {
        //     header: to_execution_payload_header(&sealed_block.header),
        //     blob_kzg_commitments: List::default(),
        //     public_key: self.public_key.clone(),
        //     value,
        // };

        Ok(sealed_block)
    }
}

pub(crate) fn to_execution_payload_header(value: &SealedHeader) -> ExecutionPayloadHeader {
    ExecutionPayloadHeader {
        parent_hash: to_bytes32(value.parent_hash),
        fee_recipient: to_bytes20(value.beneficiary),
        state_root: to_bytes32(value.state_root),
        receipts_root: to_bytes32(value.receipts_root),
        logs_bloom: to_byte_vector(value.logs_bloom),
        prev_randao: to_bytes32(value.mix_hash),
        block_number: value.number,
        gas_limit: value.gas_limit,
        gas_used: value.gas_used,
        timestamp: value.timestamp,
        extra_data: ByteList::try_from(value.extra_data.as_ref()).unwrap(),
        base_fee_per_gas: ssz_rs::U256::from(value.base_fee_per_gas.unwrap_or_default()),
        block_hash: to_bytes32(value.hash()),
        transactions_root: value.transactions_root,
        withdrawals_root: value.withdrawals_root.unwrap_or_default(),
        blob_gas_used: value.blob_gas_used.unwrap_or_default(),
        excess_blob_gas: value.excess_blob_gas.unwrap_or_default(),
    }
}

pub(crate) fn to_execution_payload(value: &SealedBlock) -> ExecutionPayload {
    let hash = value.hash();
    let header = &value.header;
    let transactions = &value.body;
    let withdrawals = &value.withdrawals;
    let transactions = transactions
        .iter()
        .map(|t| spec::Transaction::try_from(t.envelope_encoded().as_ref()).unwrap())
        .collect::<Vec<_>>();
    let withdrawals = withdrawals
        .as_ref()
        .unwrap_or(&Withdrawals::default())
        .iter()
        .map(|w| spec::Withdrawal {
            index: w.index as usize,
            validator_index: w.validator_index as usize,
            address: to_bytes20(w.address),
            amount: w.amount,
        })
        .collect::<Vec<_>>();

    let payload = spec::ExecutionPayload {
        parent_hash: to_bytes32(header.parent_hash),
        fee_recipient: to_bytes20(header.beneficiary),
        state_root: to_bytes32(header.state_root),
        receipts_root: to_bytes32(header.receipts_root),
        logs_bloom: to_byte_vector(header.logs_bloom),
        prev_randao: to_bytes32(header.mix_hash),
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: ByteList::try_from(header.extra_data.as_ref()).unwrap(),
        base_fee_per_gas: ssz_rs::U256::from(header.base_fee_per_gas.unwrap_or_default()),
        block_hash: to_bytes32(hash),
        transactions: TryFrom::try_from(transactions).unwrap(),
        withdrawals: TryFrom::try_from(withdrawals).unwrap(),
    };
    ExecutionPayload::Capella(payload)
}

fn to_bytes32(value: B256) -> spec::Bytes32 {
    spec::Bytes32::try_from(value.as_ref()).unwrap()
}

fn to_bytes20(value: Address) -> spec::ExecutionAddress {
    spec::ExecutionAddress::try_from(value.as_ref()).unwrap()
}

fn to_byte_vector(value: Bloom) -> ByteVector<256> {
    ByteVector::<256>::try_from(value.as_ref()).unwrap()
}

#[cfg(test)]
mod tests {
    use std::{borrow::BorrowMut, str::FromStr};

    use alloy_consensus::{Transaction, TxEnvelope};
    use alloy_eips::{
        calc_excess_blob_gas, calc_next_block_base_fee, eip1559::BaseFeeParams,
        eip2718::Encodable2718,
    };
    use alloy_network::{EthereumWallet, TransactionBuilder, TxSigner};
    use alloy_primitives::{address, hex, Address, Bytes, B256, U256};
    use alloy_rpc_types::TransactionRequest;
    use alloy_rpc_types_engine::{
        ExecutionPayload, ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3,
    };
    use alloy_signer::k256::ecdsa::SigningKey;
    use alloy_signer_local::PrivateKeySigner;
    use ethereum_consensus::crypto::bls::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
    use reth_primitives::{Bloom, TransactionSigned};
    use reth_rpc_layer::{secret_to_bearer_header, JwtSecret};
    use std::io::prelude::*;

    use crate::{
        builder::payload_builder::{
            to_execution_payload, ExecutionContext, FallbackPayloadBuilder, Hints, NextBlockInfo,
        },
        RpcClient,
    };

    #[tokio::test]
    async fn test_build_fallback_payload() -> eyre::Result<()> {
        dotenvy::dotenv().ok();

        let raw_sk = std::env::var("PRIVATE_KEY")?;
        let jwt = std::env::var("ENGINE_JWT")?;

        let execution_rpc = RpcClient::new("http://remotebeast:8545");
        let engine = "http://remotebeast:8551";
        let consensus = "http://remotebeast:3500";

        let pk = BlsSecretKey::random(&mut rand::thread_rng())?;

        let builder = FallbackPayloadBuilder {
            fee_recipient: Address::default(),
            public_key: pk.public_key(),
            private_key: pk,
        };

        let latest_block = execution_rpc.get_block(Some(20169768), true).await?;

        let base_fee = calc_next_block_base_fee(
            latest_block.header.gas_used,
            latest_block.header.gas_limit,
            latest_block.header.base_fee_per_gas.unwrap_or_default(),
            BaseFeeParams::ethereum(),
        );

        let excess_blob_gas = calc_excess_blob_gas(
            latest_block.header.excess_blob_gas.unwrap_or_default(),
            latest_block.header.blob_gas_used.unwrap_or_default(),
        );

        let sk = SigningKey::from_slice(hex::decode(raw_sk)?.as_slice())?;
        let signer = PrivateKeySigner::from_signing_key(sk.clone());
        let wallet = EthereumWallet::from(signer);

        let addy = Address::from_private_key(&sk);
        let mut tx = default_transaction(addy, 266);
        let tx_signed = tx.build(&wallet).await?;
        let mut raw_encoded = tx_signed.encoded_2718();
        let tx_signed_reth = TransactionSigned::decode_enveloped(&mut raw_encoded.as_slice())?;

        let execution_context = ExecutionContext {
            head_slot_number: latest_block.header.number.unwrap_or_default(),
            parent_hash: latest_block.header.hash.unwrap_or_default(),
            excess_blob_gas: excess_blob_gas as u64,
            parent_beacon_block_root: latest_block
                .header
                .parent_beacon_block_root
                .unwrap_or_default(),
            transactions: vec![tx_signed_reth],
            block: NextBlockInfo {
                number: latest_block.header.number.unwrap_or_default() + 1,
                timestamp: latest_block.header.timestamp + 12,
                prev_randao: latest_block.header.mix_hash.unwrap_or_default(),
                base_fee: base_fee as u64,
                extra_data: Bytes::from_str("0xdeadbeef")?,
                gas_limit: 30_000_000,
            },
        };

        let hints = Hints {
            gas_used: Some(21000),
            receipts_root: Some(B256::from_str(
                "0xf78dfb743fbd92ade140711c8bbc542b5e307f0ab7984eff35d751969fe57efa",
            )?),
            withdrawals_root: None,
            logs_bloom: None,
            blob_gas_used: None,
            state_root: Some(B256::from_str(
                "0x9e20f7759c74e92d0cd8ca721be834b3775dd0b7a757fcd3a26aeb3358990f5e",
            )?),
        };

        let block = builder
            .build_fallback_payload(execution_context, hints)
            .await?;

        let exec_payload_reth: ExecutionPayload = ExecutionPayload::V3(ExecutionPayloadV3 {
            blob_gas_used: block.blob_gas_used(),
            excess_blob_gas: block.excess_blob_gas.unwrap_or_default(),
            payload_inner: ExecutionPayloadV2 {
                payload_inner: ExecutionPayloadV1 {
                    base_fee_per_gas: U256::from(block.base_fee_per_gas.unwrap_or_default()),
                    block_hash: B256::from_str(
                        "1857c16c66715f087b8bf58235171b7942acf66e52c919d7526d37e523c7dcad",
                    )?,
                    block_number: block.number,
                    extra_data: block.extra_data.clone(),
                    transactions: block.raw_transactions(),
                    fee_recipient: block.header.beneficiary,
                    gas_limit: block.gas_limit,
                    gas_used: block.gas_used,
                    logs_bloom: block.logs_bloom,
                    parent_hash: block.parent_hash,
                    prev_randao: block.mix_hash,
                    receipts_root: block.receipts_root,
                    state_root: block.state_root,
                    timestamp: block.timestamp,
                },
                withdrawals: vec![],
            },
        });

        let body = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"engine_newPayloadV3","params":[{}, [], "{:?}"]}}"#,
            serde_json::to_string(&exec_payload_reth)?,
            exec_payload_reth.parent_hash()
        );

        println!("{}", body);

        let auth_jwt = secret_to_bearer_header(&JwtSecret::from_hex(jwt)?);
        let engine_client = reqwest::Client::new();
        let engine_error_1 = engine_client
            .post(engine)
            .header("Content-Type", "application/json")
            .header("Authorization", auth_jwt)
            .body(body)
            .send()
            .await?;

        let res: serde_json::Value = engine_error_1.json().await?;

        println!("{:?}", res);
        panic!();

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
