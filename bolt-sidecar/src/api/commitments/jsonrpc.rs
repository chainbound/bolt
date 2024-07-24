use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPayload {
    /// The JSON-RPC version string. MUST be "2.0".
    pub jsonrpc: String,
    /// The method string.
    pub method: String,
    /// Optional ID.
    pub id: Option<String>,
    /// The parameters object.
    pub params: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonResponse {
    pub jsonrpc: String,
    /// Optional ID. Must be serialized as `null` if not present.
    pub id: Option<String>,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub result: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonError>,
}

impl Default for JsonResponse {
    fn default() -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: None,
            result: serde_json::Value::Null,
            error: None,
        }
    }
}

impl JsonResponse {
    pub fn from_error(code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: None,
            result: serde_json::Value::Null,
            error: Some(JsonError { code, message }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonError {
    pub code: i32,
    pub message: String,
}
