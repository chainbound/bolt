use serde::{Deserialize, Serialize};

use crate::{bls::Signable, types::Slot};

/// The API parameters to request an inclusion commitment for a given slot.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InclusionRequestParams {
    pub slot: Slot,
    pub tx: String,
    pub signature: String,
}

impl Signable for InclusionRequestParams {
    fn digest(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(self.tx.as_bytes());
        data.extend_from_slice(self.signature.as_bytes());
        data
    }
}

/// The response to an inclusion request, including the request and a BLS signature.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InclusionRequestResponse {
    pub request: InclusionRequestParams,
    pub signature: String,
}
