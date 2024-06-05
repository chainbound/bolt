use alloy_rlp::Encodable;
use ethereum_consensus::deneb::{mainnet::MAX_BYTES_PER_TRANSACTION, BlsSignature, Transaction};
use ethereum_consensus::ssz::prelude::*;

use crate::{crypto::SignableBLS, primitives::InclusionRequest};

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
    pub fn build(validator_index: u64, slot: u64, request: InclusionRequest) -> Self {
        let constraints = ConstraintsList::try_from(vec![Constraint::from(request)]).unwrap();
        Self {
            validator_index,
            slot,
            constraints,
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize,
)]
pub struct Constraint {
    pub tx: Transaction<MAX_BYTES_PER_TRANSACTION>,
    pub index: Option<u64>,
}

impl From<InclusionRequest> for Constraint {
    fn from(params: InclusionRequest) -> Self {
        let mut buf: Vec<u8> = Vec::new();
        params.tx.encode(&mut buf);

        let tx = Transaction::try_from(buf.as_slice()).unwrap();

        Self { tx, index: None }
    }
}

impl SignableBLS for ConstraintsMessage {
    fn digest(&self) -> Vec<u8> {
        return ssz_rs::serialize(self).unwrap_or(Vec::new());
    }
}
