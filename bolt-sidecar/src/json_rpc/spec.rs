use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::error;

use super::api::ApiError;

/// Standard JSON-RPC error object
///
/// spec: https://www.jsonrpc.org/specification#error_object
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl warp::reject::Reject for JsonRpcError {}

/// Standard JSON-RPC request object
///
/// spec: https://www.jsonrpc.org/specification#request_object
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: serde_json::Value,
}

/// Standard JSON-RPC response object
///
/// spec: https://www.jsonrpc.org/specification#response_object
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: String,
    pub result: serde_json::Value,
}

impl From<eyre::Report> for JsonRpcError {
    fn from(err: eyre::Report) -> Self {
        Self {
            message: err.to_string(),
            code: -32000,
            data: None,
        }
    }
}

impl From<JsonRpcError> for warp::reply::Json {
    fn from(err: JsonRpcError) -> Self {
        warp::reply::json(&err)
    }
}

impl From<ApiError> for JsonRpcError {
    fn from(err: ApiError) -> Self {
        Self {
            message: err.to_string(),
            code: -32000,
            data: None,
        }
    }
}

impl From<ApiError> for warp::Rejection {
    fn from(err: ApiError) -> Self {
        error!(err = ?err, "failed to process RPC request");
        warp::reject::custom(JsonRpcError::from(err))
    }
}
