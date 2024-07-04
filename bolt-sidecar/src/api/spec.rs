use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use beacon_api_client::VersionedValue;
use ethereum_consensus::{
    builder::SignedValidatorRegistration, deneb::mainnet::SignedBlindedBeaconBlock,
};
use serde::{Deserialize, Serialize, Serializer};

use crate::primitives::{BatchedSignedConstraints, GetPayloadResponse, SignedBuilderBid};

use super::builder::GetHeaderParams;

/// The path to the builder API status endpoint.
pub const STATUS_PATH: &str = "/eth/v1/builder/status";
/// The path to the builder API register validators endpoint.
pub const REGISTER_VALIDATORS_PATH: &str = "/eth/v1/builder/validators";
/// The path to the builder API get header endpoint.
pub const GET_HEADER_PATH: &str = "/eth/v1/builder/header/:slot/:parent_hash/:pubkey";
/// The path to the builder API get payload endpoint.
pub const GET_PAYLOAD_PATH: &str = "/eth/v1/builder/blinded_blocks";
/// The path to the constraints API submit constraints endpoint.
pub const CONSTRAINTS_PATH: &str = "/eth/v1/builder/constraints";

/// A response object for errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(serialize_with = "serialize_status_code")]
    code: u16,
    message: String,
}

/// Helper to serialize a status code as a string using the provided serializer.
pub fn serialize_status_code<S>(value: &u16, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum BuilderApiError {
    #[error("No validators could be registered: {0:?}")]
    FailedRegisteringValidators(ErrorResponse),
    #[error("Failed getting header: {0:?}")]
    FailedGettingHeader(ErrorResponse),
    #[error("Failed getting payload: {0:?}")]
    FailedGettingPayload(ErrorResponse),
    #[error("Failed submitting constraints: {0:?}")]
    FailedSubmittingConstraints(ErrorResponse),
    #[error("Failed to fetch local payload for slot {0}")]
    FailedToFetchLocalPayload(u64),
    #[error("Axum error: {0:?}")]
    AxumError(#[from] axum::Error),
    #[error("Json error: {0:?}")]
    JsonError(#[from] serde_json::Error),
    #[error("Reqwest error: {0:?}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("API request timed out : {0:?}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Invalid fork: {0}")]
    InvalidFork(String),
    #[error("Invalid local payload block hash. expected: {expected}, got: {have}")]
    InvalidLocalPayloadBlockHash { expected: String, have: String },
}

impl IntoResponse for BuilderApiError {
    fn into_response(self) -> Response {
        match self {
            BuilderApiError::FailedRegisteringValidators(error) => {
                (StatusCode::from_u16(error.code).unwrap(), Json(error)).into_response()
            }
            BuilderApiError::FailedGettingHeader(error) => {
                (StatusCode::from_u16(error.code).unwrap(), Json(error)).into_response()
            }
            BuilderApiError::FailedGettingPayload(error) => {
                (StatusCode::from_u16(error.code).unwrap(), Json(error)).into_response()
            }
            BuilderApiError::FailedSubmittingConstraints(error) => {
                (StatusCode::from_u16(error.code).unwrap(), Json(error)).into_response()
            }
            BuilderApiError::AxumError(err) => {
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
            BuilderApiError::JsonError(err) => {
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
            BuilderApiError::FailedToFetchLocalPayload(_) => {
                (StatusCode::NO_CONTENT, self.to_string()).into_response()
            }
            BuilderApiError::ReqwestError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                StatusCode::INTERNAL_SERVER_ERROR
                    .canonical_reason()
                    .unwrap(),
            )
                .into_response(),
            BuilderApiError::Timeout(_) => (
                StatusCode::GATEWAY_TIMEOUT,
                StatusCode::GATEWAY_TIMEOUT.canonical_reason().unwrap(),
            )
                .into_response(),
            BuilderApiError::InvalidFork(err) => {
                (StatusCode::BAD_REQUEST, Json(err)).into_response()
            }
            BuilderApiError::InvalidLocalPayloadBlockHash { .. } => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
        }
    }
}

#[async_trait::async_trait]
/// Implements the builder API as defines in <https://ethereum.github.io/builder-specs>
pub trait BuilderApi {
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/status>
    async fn status(&self) -> Result<StatusCode, BuilderApiError>;
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/registerValidator>
    async fn register_validators(
        &self,
        registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), BuilderApiError>;
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/getHeader>
    async fn get_header(
        &self,
        params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, BuilderApiError>;
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock>
    async fn get_payload(
        &self,
        signed_block: SignedBlindedBeaconBlock,
    ) -> Result<GetPayloadResponse, BuilderApiError>;
}

#[async_trait::async_trait]
/// Implements the constraints API as defines in <https://chainbound.github.io/bolt-docs/api/builder-api>
pub trait ConstraintsApi: BuilderApi {
    /// Implements: <https://chainbound.github.io/bolt-docs/api/builder-api#ethv1builderconstraints>
    async fn submit_constraints(
        &self,
        constraints: &BatchedSignedConstraints,
    ) -> Result<(), BuilderApiError>;

    /// Implements: <https://chainbound.github.io/bolt-docs/api/builder-api#ethv1builderheader_with_proofsslotparent_hashpubkey>
    async fn get_header_with_proofs(
        &self,
        params: GetHeaderParams,
    ) -> Result<VersionedValue<SignedBuilderBid>, BuilderApiError>;
}
