use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Bytes, TxHash, U256};
use ethereum_consensus::deneb::{mainnet::MAX_BYTES_PER_TRANSACTION, BlsSignature, Transaction};
use ethereum_consensus::ssz::prelude::*;

use crate::crypto::SignableBLS;

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

/// The inclusion request transformed into an explicit list of signed constraints
/// that need to be forwarded to the PBS pipeline to inform block production.
pub type BatchedSignedConstraints = Vec<SignedConstraints>;

const MAX_CONSTRAINTS_PER_SLOT: usize = 256;

#[derive(Debug, Clone, PartialEq, SimpleSerialize, serde::Deserialize, serde::Serialize)]
pub struct SignedConstraints {
    pub message: ConstraintsMessage,
    pub signature: BlsSignature,
}

#[derive(
    Debug, Clone, Default, PartialEq, SimpleSerialize, serde::Deserialize, serde::Serialize,
)]
pub struct ConstraintsMessage {
    pub validator_index: u64,
    pub slot: u64,
    pub constraints: List<Constraint, MAX_CONSTRAINTS_PER_SLOT>,
}

type ConstraintsList = List<Constraint, MAX_CONSTRAINTS_PER_SLOT>;

impl ConstraintsMessage {
    pub fn build(validator_index: u64, slot: u64, request: InclusionRequest) -> eyre::Result<Self> {
        let constraints = ConstraintsList::try_from(vec![Constraint::try_from(request)?])
            .map_err(|e| eyre::eyre!("Failed to build ConstraintsMessage: {:?}", e))?;

        Ok(Self {
            validator_index,
            slot,
            constraints,
        })
    }
}

#[derive(
    Debug, Clone, PartialEq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct Constraint {
    pub tx: Transaction<MAX_BYTES_PER_TRANSACTION>,
    pub index: Option<u64>,
}

impl TryFrom<InclusionRequest> for Constraint {
    type Error = eyre::Error;

    fn try_from(params: InclusionRequest) -> Result<Self, Self::Error> {
        let mut buf: Vec<u8> = Vec::new();
        params.tx.encode_2718(&mut buf);

        let tx = Transaction::try_from(buf.as_slice())?;

        Ok(Self { tx, index: None })
    }
}

impl SignableBLS for ConstraintsMessage {
    fn digest(&self) -> Vec<u8> {
        ssz_rs::serialize(self).unwrap_or_default()
    }
}
