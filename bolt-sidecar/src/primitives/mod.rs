use alloy_primitives::{Bytes, TxHash, U256};

pub mod commitment;
pub use commitment::{CommitmentRequest, InclusionRequest};

pub mod transaction;
pub use transaction::TxInfo;

/// An alias for a Beacon Chain slot number
pub type Slot = u64;

/// An enum representing all possible (signed) commitments.
#[derive(Debug)]
pub enum Commitment {
    /// Inclusion commitment, accepted and signed by the proposer
    /// through this sidecar's signer.
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

/// Minimal account state needed for commitment validation.
#[derive(Debug, Clone, Copy)]
pub struct AccountState {
    /// The nonce of the account. This is the number of transactions sent from this account
    pub transaction_count: u64,
    pub balance: U256,
}
