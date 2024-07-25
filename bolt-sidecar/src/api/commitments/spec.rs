use alloy::primitives::SignatureError;
use axum::{extract::rejection::JsonRejection, http::StatusCode, response::IntoResponse, Json};
use thiserror::Error;

use crate::primitives::{commitment::InclusionCommitment, InclusionRequest};

use super::jsonrpc::JsonResponse;

pub(super) const SIGNATURE_HEADER: &str = "x-bolt-signature";

pub(super) const REQUEST_INCLUSION_METHOD: &str = "bolt_requestInclusion";

#[derive(Debug, Error)]
pub enum Error {
    #[error("Request rejected: {0}")]
    Rejected(#[from] RejectionError),
    #[error("{0}")]
    ValidationFailed(String),
    #[error("Duplicate request")]
    Duplicate,
    #[error("Internal server error")]
    Internal,
    #[error("Missing X-Bolt-Signature header")]
    NoSignature,
    #[error(transparent)]
    InvalidSignature(#[from] crate::primitives::SignatureError),
    #[error(transparent)]
    Signature(#[from] SignatureError),
    #[error("Unknown method")]
    UnknownMethod,
    #[error(transparent)]
    InvalidJson(#[from] JsonRejection),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        match self {
            Error::Rejected(err) => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32000, err.to_string())),
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
            Error::InvalidSignature(err) => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32004, err.to_string())),
            )
                .into_response(),
            Error::Signature(err) => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32005, err.to_string())),
            )
                .into_response(),
            Error::ValidationFailed(message) => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32006, message)),
            )
                .into_response(),
            Error::UnknownMethod => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(-32601, self.to_string())),
            )
                .into_response(),
            Error::InvalidJson(err) => (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse::from_error(
                    -32600,
                    format!("Invalid request: {err}"),
                )),
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
