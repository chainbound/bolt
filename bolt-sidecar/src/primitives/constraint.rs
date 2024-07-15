use alloy_primitives::{keccak256, Address};
use reth_primitives::PooledTransactionsElement;
use secp256k1::Message;
use serde::{Deserialize, Serialize};

use crate::crypto::{ecdsa::SignableECDSA, SignableBLS};

use super::InclusionRequest;

/// What the proposer sidecar will need to sign to confirm the inclusion request.
impl SignableECDSA for ConstraintsMessage {
    fn digest(&self) -> Message {
        let mut data = Vec::new();
        data.extend_from_slice(&self.validator_index.to_le_bytes());
        data.extend_from_slice(&self.slot.to_le_bytes());

        let mut constraint_bytes = Vec::new();
        for constraint in &self.constraints {
            constraint_bytes.extend_from_slice(&constraint.as_bytes());
        }
        data.extend_from_slice(&constraint_bytes);

        let hash = keccak256(data).0;
        Message::from_digest_slice(&hash).expect("digest")
    }
}

/// The inclusion request transformed into an explicit list of signed constraints
/// that need to be forwarded to the PBS pipeline to inform block production.
pub type BatchedSignedConstraints = Vec<SignedConstraints>;

/// A container for a list of constraints and the signature of the proposer sidecar.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct SignedConstraints {
    /// The constraints that need to be signed.
    pub message: ConstraintsMessage,
    /// The signature of the proposer sidecar.
    pub signature: String,
}

/// A message that contains the constraints that need to be signed by the proposer sidecar.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ConstraintsMessage {
    /// The validator index of the proposer sidecar.
    pub validator_index: u64,
    /// The consensus slot at which the constraints are valid
    pub slot: u64,
    /// The constraints that need to be signed.
    pub constraints: Vec<Constraint>,
}

impl ConstraintsMessage {
    /// Builds a constraints message from an inclusion request and metadata
    pub fn build(
        validator_index: u64,
        slot: u64,
        request: InclusionRequest,
        sender: Address,
    ) -> Self {
        let constraints = vec![Constraint::from_transaction(request.tx, None, sender)];
        Self {
            validator_index,
            slot,
            constraints,
        }
    }
}

impl SignableBLS for ConstraintsMessage {
    fn digest(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.validator_index.to_le_bytes());
        data.extend_from_slice(&self.slot.to_le_bytes());

        let mut constraint_bytes = Vec::new();
        for constraint in &self.constraints {
            constraint_bytes.extend_from_slice(&constraint.as_bytes());
        }
        data.extend_from_slice(&constraint_bytes);

        keccak256(data).0.to_vec()
    }
}

/// A general constraint on block building.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Constraint {
    /// The optional index at which the transaction needs to be included in the block
    pub index: Option<u64>,
    /// The transaction to be included in the block
    pub(crate) transaction: PooledTransactionsElement,
    /// The ec-recovered address of the transaction sender for internal use
    #[serde(skip)]
    pub(crate) sender: Address,
}

impl Constraint {
    /// Builds a constraint from a transaction, with an optional index
    pub fn from_transaction(
        transaction: PooledTransactionsElement,
        index: Option<u64>,
        sender: Address,
    ) -> Self {
        Self {
            transaction,
            index,
            sender,
        }
    }

    /// Converts the constraint to a byte representation useful for signing
    /// TODO: remove if we go with SSZ
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.transaction.encode_enveloped(&mut data);
        data.extend_from_slice(&self.index.unwrap_or(0).to_le_bytes());
        data
    }
}
