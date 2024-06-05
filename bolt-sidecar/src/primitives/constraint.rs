use alloy_primitives::keccak256;
use secp256k1::Message;
use serde::{Deserialize, Serialize};

use crate::{crypto::SignableECDSA, types::Slot};

/// The API parameters to request an inclusion commitment for a given slot.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InclusionRequestParams {
    #[serde(flatten)]
    pub message: InclusionRequestMessage,
    pub signature: String,
}

/// The message to request an inclusion commitment for a given slot.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InclusionRequestMessage {
    pub slot: Slot,
    pub tx: String,
    pub index: Option<u64>,
}

/// What users have to sign to request an inclusion commitment.
/// We use the [SignableECDSA] trait to abstract over the signature verification step.
impl SignableECDSA for InclusionRequestMessage {
    fn digest(&self) -> Message {
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(self.tx.as_bytes());
        data.extend_from_slice(&self.index.unwrap_or(0).to_le_bytes());

        let hash = keccak256(data).0;
        Message::from_digest_slice(&hash).expect("digest")
    }
}

impl From<InclusionRequestParams> for Constraint {
    fn from(params: InclusionRequestParams) -> Self {
        Self {
            tx: params.message.tx,
            index: params.message.index,
        }
    }
}

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedConstraints {
    pub message: ConstraintsMessage,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ConstraintsMessage {
    pub validator_index: u64,
    pub slot: u64,
    pub constraints: Vec<Constraint>,
}

impl ConstraintsMessage {
    pub fn build(validator_index: u64, slot: u64, request: InclusionRequestParams) -> Self {
        let constraints = vec![Constraint::from(request)];
        Self {
            validator_index,
            slot,
            constraints,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Constraint {
    pub tx: String,
    pub index: Option<u64>,
}

impl Constraint {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.tx.as_bytes());
        data.extend_from_slice(&self.index.unwrap_or(0).to_le_bytes());
        data
    }
}
