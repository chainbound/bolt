use alloy_primitives::{Bytes, Signature, TxHash};
use alloy_rpc_types::Transaction;

use crate::types::Slot;

/// A request for a proposer commitment.
///
/// # Encoding
/// We use RLP encoding for the commitment request. It must include a signature.
#[derive(Debug, Clone)]
pub enum CommitmentRequest {
    /// Inclusion request.
    Inclusion(InclusionRequest),
}

// /// A request for inclusion, a.k.a. inclusion preconfirmation.
// #[derive(Debug, Clone)]
// pub struct InclusionRequest {
//     pub slot: Slot,
//     pub tx_hash: TxHash,
//     pub raw_tx: Bytes,
//     pub signature: Bytes,
//     pub sender: Address,
// }

/// A request for inclusion, a.k.a. inclusion preconfirmation.
#[derive(Debug, Clone)]
pub struct InclusionRequest {
    /// The target slot
    pub slot: Slot,
    /// The signed, typed transaction.
    pub transaction: Transaction,
    /// The signature for the request.
    pub signature: Signature,
}

impl InclusionRequest {
    /// Validates the transaction fee against a minimum basefee. Returns true if the
    /// fee is greater than or equal, false otherwise.
    pub fn validate_basefee(&self, min: u128) -> bool {
        if let Some(max_fee) = self.transaction.max_fee_per_gas {
            if max_fee < min {
                return false;
            }
        } else if let Some(fee) = self.transaction.gas_price {
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
