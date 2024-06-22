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
    TransactionSigned, EMPTY_OMMER_ROOT_HASH,
};

use crate::primitives::{BuilderBid, Slot};

#[derive(Debug, thiserror::Error)]
pub enum PayloadBuilderError {
    #[error("Failed to build payload: {0}")]
    Custom(String),
}

#[derive(Debug)]
pub struct FallbackPayloadBuilder<SRP>
where
    SRP: StateRootProvider,
{
    state_root_provider: SRP,

    fee_recipient: Address,

    // keypair used for signing the payload
    private_key: BlsSecretKey,
    public_key: BlsPublicKey,
}

/// Minimal execution context required to build a valid payload on the target slot.
#[derive(Debug)]
pub struct ExecutionContext {
    head_slot_number: Slot,
    parent_hash: B256,
    transactions: Vec<TransactionSigned>,
    block: NextBlockInfo,
}

#[derive(Debug)]
pub struct NextBlockInfo {
    number: u64,
    timestamp: u64,
    prev_randao: B256,
    base_fee: u64,
    extra_data: Bytes,
    gas_limit: u64,
}

/// Provider that is able to compute the state root over a set of state diffs.
/// TODO: how do we avoid full access to the state DB here?
pub trait StateRootProvider {
    fn get_state_root(&self) -> Result<B256, PayloadBuilderError>;
}

impl<SRP> FallbackPayloadBuilder<SRP>
where
    SRP: StateRootProvider,
{
    /// Build a minimal payload to be used as a fallback
    pub async fn build_fallback_payload(
        &self,
        context: ExecutionContext,
    ) -> Result<BuilderBid, PayloadBuilderError> {
        // TODO: actually get the state root (needs to count post-state diffs)
        let state_root = self.state_root_provider.get_state_root()?;
        let transactions_root = proofs::calculate_transaction_root(&context.transactions);

        // TODO: fill all of these with correct values
        let withdrawals_root = Some(B256::default());
        let receipts_root = B256::default();
        let logs_bloom = Bloom::default();
        let gas_used = 0;
        let parent_beacon_root = B256::default();
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
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: Some(parent_beacon_root),
            extra_data: context.block.extra_data,
        };

        let body = BlockBody {
            transactions: context.transactions,
            ommers: Vec::new(),
            withdrawals: None,
        };

        let sealed_block = SealedBlock::new(header.seal_slow(), body);
        let submission = BuilderBid {
            header: to_execution_payload_header(&sealed_block.header),
            blob_kzg_commitments: List::default(),
            public_key: self.public_key.clone(),
            value,
        };

        Ok(submission)
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
        .unwrap()
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
