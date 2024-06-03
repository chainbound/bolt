use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, Bytes, Signature, TxHash, U256};
use alloy_rpc_types::Transaction;

use crate::types::Slot;

use super::transaction::TxInfo;

/// A request for a proposer commitment.
///
/// # Encoding
/// We use RLP encoding for the commitment request. It must include a signature.
#[derive(Debug, Clone)]
pub enum CommitmentRequest {
    /// Inclusion request.
    Inclusion(InclusionRequest<TxEnvelope>),
}

/// A request for inclusion, a.k.a. inclusion preconfirmation.
#[derive(Debug, Clone)]
pub struct InclusionRequest<T> {
    /// The target slot
    pub slot: Slot,
    /// The signed, typed transaction.
    pub transaction: T,
    /// The signature for the request.
    pub signature: Signature,
}

impl<T: TxInfo> InclusionRequest<T> {
    /// Validates the transaction fee against a minimum basefee. Returns true if the
    /// fee is greater than or equal, false otherwise.
    pub fn validate_basefee(&self, min: u128) -> bool {
        if let Some(max_fee) = self.transaction.max_fee_per_gas() {
            if max_fee < min {
                return false;
            }
        } else if let Some(fee) = self.transaction.gas_price() {
            if fee < min {
                return false;
            }
        } else {
            unreachable!("Transaction must have a fee");
        }

        true
    }
}

/// An enum representing all possible (signed) commitments.
#[derive(Debug)]
pub enum Commitment {
    Inclusion(InclusionCommitment),
}

#[derive(Debug)]
pub struct InclusionCommitment {
    pub slot: Slot,
    pub tx_hash: TxHash,
    pub raw_tx: Bytes,
    // TODO:
    pub signature: Bytes,
}
