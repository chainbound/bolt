use serde::{Deserialize, Serialize};
use tracing::error;

use super::api::PreconfirmationError;
use crate::traits::Signable;

/// Slot number type alias
pub(crate) type Slot = u64;

/// Parameters for a preconfirmation request.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreconfirmationRequestParams {
    pub(crate) tx: String,
    pub(crate) slot: Slot,
    pub(crate) signature: String,
}

impl Signable for PreconfirmationRequestParams {
    fn as_signable(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&hex::decode(&self.tx[2..]).unwrap());
        bytes.extend_from_slice(&self.slot.to_be_bytes());
        bytes
    }
}

/// Response to a preconfirmation request.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreconfirmationResponse {
    pub(crate) request: PreconfirmationRequestParams,
    pub(crate) proposer_signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetPreconfirmationsAtSlotParams {
    pub(crate) slot: Slot,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl warp::reject::Reject for JsonRpcError {}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JsonRpcRequest {
    pub(crate) jsonrpc: String,
    pub(crate) id: String,
    pub(crate) method: String,
    pub(crate) params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JsonRpcResponse {
    pub(crate) jsonrpc: String,
    pub(crate) id: String,
    pub(crate) result: serde_json::Value,
}

impl From<eyre::Report> for JsonRpcError {
    fn from(err: eyre::Report) -> Self {
        Self {
            code: -32000,
            message: err.to_string(),
        }
    }
}

impl From<JsonRpcError> for warp::reply::Json {
    fn from(err: JsonRpcError) -> Self {
        warp::reply::json(&err)
    }
}

impl From<PreconfirmationError> for JsonRpcError {
    fn from(err: PreconfirmationError) -> Self {
        Self {
            code: -32000,
            message: err.to_string(),
        }
    }
}

impl From<PreconfirmationError> for warp::Rejection {
    fn from(err: PreconfirmationError) -> Self {
        error!(err = ?err, "failed to process RPC request");
        warp::reject::custom(JsonRpcError::from(err))
    }
}
