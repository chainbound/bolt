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
}

/// What users will need to sign to request an inclusion commitment.
impl SignableECDSA for InclusionRequestMessage {
    fn digest(&self) -> Message {
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(self.tx.as_bytes());

        let hash = keccak256(data).0;
        Message::from_digest_slice(&hash).expect("digest")
    }
}

/// What the proposer sidecar will need to sign to confirm the inclusion request.
impl SignableECDSA for InclusionRequestParams {
    fn digest(&self) -> Message {
        let mut data = Vec::new();
        data.extend_from_slice(&self.message.slot.to_le_bytes());
        data.extend_from_slice(self.message.tx.as_bytes());
        data.extend_from_slice(self.signature.as_bytes());

        let hash = keccak256(data).0;
        Message::from_digest_slice(&hash).expect("digest")
    }
}

/// The response to an inclusion request, including the request and a BLS signature.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InclusionRequestResponse {
    pub request: InclusionRequestParams,
    pub signature: String,
}
