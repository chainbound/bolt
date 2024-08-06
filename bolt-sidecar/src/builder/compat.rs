use alloy::{
    eips::eip4895::Withdrawal,
    primitives::{Address, Bloom, B256, U256},
    rpc::types::engine::{
        ExecutionPayload as AlloyExecutionPayload, ExecutionPayloadV1, ExecutionPayloadV2,
        ExecutionPayloadV3,
    },
};
use ethereum_consensus::{
    bellatrix::mainnet::Transaction,
    capella::spec,
    deneb::{
        mainnet::{
            ExecutionPayloadHeader as ConsensusExecutionPayloadHeader,
            Withdrawal as ConsensusWithdrawal, MAX_TRANSACTIONS_PER_PAYLOAD,
            MAX_WITHDRAWALS_PER_PAYLOAD,
        },
        ExecutionAddress, ExecutionPayload as DenebExecutionPayload,
    },
    ssz::prelude::{ssz_rs, ByteList, ByteVector, HashTreeRoot, List},
    types::mainnet::ExecutionPayload as ConsensusExecutionPayload,
};
use reth_primitives::{SealedBlock, TransactionSigned, Withdrawals};

/// Compatibility: convert a sealed header into an ethereum-consensus execution payload header.
/// This requires recalculating the withdrals and transactions roots as SSZ instead of MPT roots.
pub(crate) fn to_execution_payload_header(
    sealed_block: &SealedBlock,
    transactions: Vec<TransactionSigned>,
) -> ConsensusExecutionPayloadHeader {
    // Transactions and withdrawals are treated as opaque byte arrays in consensus types
    let transactions_bytes = transactions.iter().map(|t| t.envelope_encoded()).collect::<Vec<_>>();

    let mut transactions_ssz: List<Transaction, MAX_TRANSACTIONS_PER_PAYLOAD> = List::default();

    for tx in transactions_bytes {
        transactions_ssz.push(Transaction::try_from(tx.as_ref()).unwrap());
    }

    let transactions_root = transactions_ssz.hash_tree_root().expect("valid transactions root");

    let mut withdrawals_ssz: List<ConsensusWithdrawal, MAX_WITHDRAWALS_PER_PAYLOAD> =
        List::default();

    if let Some(withdrawals) = sealed_block.withdrawals.as_ref() {
        for w in withdrawals.iter() {
            withdrawals_ssz.push(to_consensus_withdrawal(w));
        }
    }

    let withdrawals_root = withdrawals_ssz.hash_tree_root().expect("valid withdrawals root");

    let header = &sealed_block.header;

    ConsensusExecutionPayloadHeader {
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
        block_hash: to_bytes32(header.hash()),
        blob_gas_used: header.blob_gas_used.unwrap_or_default(),
        excess_blob_gas: header.excess_blob_gas.unwrap_or_default(),
        transactions_root,
        withdrawals_root,
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

    let payload = DenebExecutionPayload {
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
        blob_gas_used: value.blob_gas_used(),
        excess_blob_gas: value.excess_blob_gas.unwrap_or_default(),
    };
    ConsensusExecutionPayload::Deneb(payload)
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

/// Compatibility: convert a withdrawal from Reth to ethereum-consensus
pub(crate) fn to_consensus_withdrawal(
    value: &reth_primitives::Withdrawal,
) -> ethereum_consensus::capella::Withdrawal {
    ethereum_consensus::capella::Withdrawal {
        index: value.index as usize,
        validator_index: value.validator_index as usize,
        address: ExecutionAddress::try_from(value.address.as_ref()).unwrap(),
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
