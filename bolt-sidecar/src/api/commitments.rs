use alloy::primitives::Signature;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, str::FromStr, sync::Arc};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::primitives::{
    commitment::{Commitment, InclusionCommitment},
    BlsSignature, CommitmentRequest, InclusionRequest,
};

const SIGNATURE_HEADER: &str = "x-bolt-signature";

const REQUEST_INCLUSION_METHOD: &str = "bolt_requestInclusion";

#[derive(Debug, Error)]
pub enum Error {
    #[error("Request rejected: {0}")]
    Rejected(#[from] RejectionError),
    #[error("Duplicate request")]
    Duplicate,
    #[error("Internal server error")]
    Internal,
    #[error("Missing signature in X-Bolt-Signature header")]
    NoSignature,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Unknown method")]
    UnknownMethod,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        match self {
            Error::Rejected(error) => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32000, error.to_string())),
            )
                .into_response(),
            Error::Duplicate => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32001, self.to_string())),
            )
                .into_response(),
            Error::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(JsonResponse::from_error(-32002, self.to_string())),
            )
                .into_response(),
            Error::NoSignature => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32003, self.to_string())),
            )
                .into_response(),
            Error::InvalidSignature => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32004, self.to_string())),
            )
                .into_response(),
            Error::UnknownMethod => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32601, self.to_string())),
            )
                .into_response(),
        }
    }
}

/// Error indicating the rejection of a commitment request. This should
/// be returned to the user.
#[derive(Debug, Error)]
pub enum RejectionError {
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

/// Implements the commitments-API: <https://chainbound.github.io/bolt-docs/api/rpc>
#[async_trait::async_trait]
pub trait CommitmentsApi {
    /// Implements: <https://chainbound.github.io/bolt-docs/api/rpc#bolt_requestinclusion>
    async fn request_inclusion(
        &self,
        inclusion_request: InclusionRequest,
    ) -> Result<InclusionCommitment, Error>;
}

struct Event {
    request: CommitmentRequest,
    response: oneshot::Sender<Result<Commitment, RejectionError>>,
}

/// The inner commitments-API handler that implements the [CommitmentsApi] spec.
/// Should be wrapped by a [CommitmentsApiServer] JSON-RPC server to handle requests.
pub struct CommitmentsApiInner {
    /// Event notification channel
    events: mpsc::Sender<Event>,
    /// Optional whitelist of ECDSA public keys
    whitelist: Option<HashSet<PublicKey>>,
}

impl CommitmentsApiInner {
    /// Create a new API server with an optional whitelist of ECDSA public keys.
    pub fn new(events: mpsc::Sender<Event>) -> Self {
        Self {
            events,
            whitelist: None,
        }
    }
}

#[async_trait::async_trait]
impl CommitmentsApi for CommitmentsApiInner {
    async fn request_inclusion(
        &self,
        inclusion_request: InclusionRequest,
    ) -> Result<InclusionCommitment, Error> {
        let (response_tx, response_rx) = oneshot::channel();

        let event = Event {
            request: CommitmentRequest::Inclusion(inclusion_request),
            response: response_tx,
        };

        self.events.send(event).await.unwrap();

        response_rx
            .await
            .map_err(|_| Error::Internal)?
            .map(|c| c.into())
            .map_err(Error::Rejected)
    }
}

/// The outer commitments-API JSON-RPC server that wraps the [CommitmentsApiInner] handler.
pub struct CommitmentsApiServer;

impl CommitmentsApiServer {
    /// Handler function for the root JSON-RPC path.
    #[tracing::instrument(skip(api))]
    async fn handle_rpc(
        State(api): State<Arc<CommitmentsApiInner>>,
        headers: HeaderMap,
        Json(payload): Json<JsonPayload>,
    ) -> Result<JsonResponse, Error> {
        let signature = headers.get(SIGNATURE_HEADER).ok_or({
            tracing::error!("Missing signature");
            Error::NoSignature
        })?;
        tracing::debug!("Received new request");

        match payload.method.as_str() {
            REQUEST_INCLUSION_METHOD => {
                // Parse the inclusion request from the parameters
                let mut inclusion_request: InclusionRequest =
                    serde_json::from_value(payload.params.clone())
                        .map_err(|e| RejectionError::ValidationFailed(e.to_string()))?;

                inclusion_request.signature = Signature::from_str(signature.to_str().unwrap())
                    .map_err(|_| Error::InvalidSignature)?;

                let inclusion_commitment = api.request_inclusion(inclusion_request).await?;

                // Create the JSON-RPC response
                let response = JsonResponse {
                    id: payload.id,
                    result: serde_json::to_value(inclusion_commitment).unwrap(),
                    ..Default::default()
                };

                Ok(response)
            }
            _ => {
                tracing::error!("Unknown method: {}", payload.method);
                Err(Error::UnknownMethod)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPayload {
    /// The JSON-RPC version string. MUST be "2.0".
    pub jsonrpc: String,
    /// The method string.
    pub method: String,
    /// Optional ID.
    pub id: Option<String>,
    /// The parameters object.
    pub params: serde_json::Value,
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
    fn from_error(code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: None,
            result: serde_json::Value::Null,
            error: Some(JsonError { code, message }),
        }
    }

    fn set_id(&mut self, id: Option<String>) {
        self.id = id;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonError {
    pub code: i32,
    pub message: String,
}
