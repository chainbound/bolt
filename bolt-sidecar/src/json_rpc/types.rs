use serde::{Deserialize, Serialize};
use tracing::error;

use super::api::PreconfirmationError;

pub type Slot = u64;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PreconfirmationRequestParams {
    pub slot: Slot,
    pub tx_hash: String,
    pub raw_tx: String,
}

impl PreconfirmationRequestParams {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.slot.to_be_bytes());
        bytes.extend_from_slice(&hex::decode(&self.tx_hash[2..]).unwrap());
        bytes.extend_from_slice(&hex::decode(&self.raw_tx[2..]).unwrap());
        bytes
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl warp::reject::Reject for JsonRpcError {}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: String,
    pub result: serde_json::Value,
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
