use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPayload {
    /// The JSON-RPC version string. MUST be "2.0".
    pub jsonrpc: String,
    /// The method string.
    pub method: String,
    /// Optional ID.
    pub id: Option<Value>,
    /// The parameters object.
    pub params: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonResponse {
    pub jsonrpc: String,
    /// Optional ID. Must be serialized as `null` if not present.
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Value::is_null", default)]
    pub result: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonError>,
}

impl Default for JsonResponse {
    fn default() -> Self {
        Self { jsonrpc: "2.0".to_string(), id: None, result: Value::Null, error: None }
    }
}

impl JsonResponse {
    pub fn from_error(code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: None,
            result: Value::Null,
            error: Some(JsonError { code, message }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonError {
    pub code: i32,
    pub message: String,
}
