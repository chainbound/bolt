use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ethereum_consensus::{
    builder::SignedValidatorRegistration, deneb::mainnet::SignedBlindedBeaconBlock,
};
use serde::{Deserialize, Serialize, Serializer};

use crate::types::{GetPayloadResponse, SignedBuilderBid};

use super::builder::GetHeaderParams;

pub const STATUS_PATH: &str = "/eth/v1/builder/status";
pub const REGISTER_VALIDATORS_PATH: &str = "/eth/v1/builder/validators";
pub const GET_HEADER_PATH: &str = "/eth/v1/builder/header/:slot/:parent_hash/:pubkey";
pub const GET_HEADER_WITH_PROOFS_PATH: &str =
    "/eth/v1/builder/header_with_proofs/:slot/:parent_hash/:pubkey";
pub const GET_PAYLOAD_PATH: &str = "/eth/v1/builder/blinded_blocks";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(serialize_with = "serialize_status_code")]
    code: u16,
    message: String,
}

pub fn serialize_status_code<S>(value: &u16, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

#[derive(Debug, thiserror::Error)]
pub enum BuilderApiError {
    #[error("No validators could be registered: {0:?}")]
    FailedRegisteringValidators(ErrorResponse),
    #[error("Failed getting header: {0:?}")]
    FailedGettingHeader(ErrorResponse),
    #[error("Failed getting payload: {0:?}")]
    FailedGettingPayload(ErrorResponse),
    #[error("Failed to fetch local payload for slot {0}")]
    FailedToFetchLocalPayload(u64),
    #[error("Axum error: {0:?}")]
    AxumError(#[from] axum::Error),
    #[error("Json error: {0:?}")]
    JsonError(#[from] serde_json::Error),
    #[error("Reqwest error: {0:?}")]
    ReqwestError(#[from] reqwest::Error),
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
        }
    }
}

#[async_trait::async_trait]
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
pub trait ConstraintsApi: BuilderApi {
    async fn submit_constraints(&self, constraints: String) -> Result<(), BuilderApiError>;

    async fn get_header_with_proofs(
        &self,
        params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, BuilderApiError>;
}
