use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{Address, Bloom, B256, U256};
use alloy_rpc_types_engine::{
    ExecutionPayload as AlloyExecutionPayload, ExecutionPayloadV1, ExecutionPayloadV2,
    ExecutionPayloadV3,
};
use ethereum_consensus::{
    capella::spec,
    deneb::mainnet::ExecutionPayloadHeader as ConsensusExecutionPayloadHeader,
    ssz::prelude::{ssz_rs, ByteList, ByteVector},
    types::mainnet::ExecutionPayload as ConsensusExecutionPayload,
};
use reth_primitives::{SealedBlock, SealedHeader, Withdrawals};

/// Compatibility: convert a sealed header into an ethereum-consensus execution payload header
pub(crate) fn to_execution_payload_header(value: &SealedHeader) -> ConsensusExecutionPayloadHeader {
    ConsensusExecutionPayloadHeader {
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

/// Compatibility: convert a sealed block into an Alloy execution payload
pub(crate) fn to_alloy_execution_payload(
    block: &SealedBlock,
    block_hash: B256,
) -> AlloyExecutionPayload {
    let alloy_withdrawals = block
        .withdrawals
        .as_ref()
        .map(|withdrawals| {
            withdrawals
                .iter()
                .map(|w| Withdrawal {
                    index: w.index,
                    validator_index: w.validator_index,
                    address: w.address,
                    amount: w.amount,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    AlloyExecutionPayload::V3(ExecutionPayloadV3 {
        blob_gas_used: block.blob_gas_used(),
        excess_blob_gas: block.excess_blob_gas.unwrap_or_default(),
        payload_inner: ExecutionPayloadV2 {
            payload_inner: ExecutionPayloadV1 {
                base_fee_per_gas: U256::from(block.base_fee_per_gas.unwrap_or_default()),
                block_hash,
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
            withdrawals: alloy_withdrawals,
        },
    })
}

/// Compatibility: convert a sealed block into an ethereum-consensus execution payload
pub(crate) fn to_consensus_execution_payload(value: &SealedBlock) -> ConsensusExecutionPayload {
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
    ConsensusExecutionPayload::Capella(payload)
}

/// Compatibility: convert a withdrawal from ethereum-consensus to a Reth withdrawal
pub(crate) fn to_reth_withdrawal(
    value: ethereum_consensus::capella::Withdrawal,
) -> reth_primitives::Withdrawal {
    reth_primitives::Withdrawal {
        index: value.index as u64,
        validator_index: value.validator_index as u64,
        address: Address::from_slice(value.address.as_ref()),
        amount: value.amount,
    }
}

pub(crate) fn to_bytes32(value: B256) -> spec::Bytes32 {
    spec::Bytes32::try_from(value.as_ref()).unwrap()
}

pub(crate) fn to_bytes20(value: Address) -> spec::ExecutionAddress {
    spec::ExecutionAddress::try_from(value.as_ref()).unwrap()
}

pub(crate) fn to_byte_vector(value: Bloom) -> ByteVector<256> {
    ByteVector::<256>::try_from(value.as_ref()).unwrap()
}
