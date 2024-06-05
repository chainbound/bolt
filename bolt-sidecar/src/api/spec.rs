use axum::{body::Body, http::StatusCode};
use ethereum_consensus::{
    builder::SignedValidatorRegistration, deneb::mainnet::SignedBlindedBeaconBlock,
};

use crate::types::SignedBuilderBid;

use super::builder::GetHeaderParams;

pub const STATUS_PATH: &str = "/eth/v1/builder/status";
pub const REGISTER_VALIDATORS_PATH: &str = "/eth/v1/builder/validators";
pub const GET_HEADER_PATH: &str = "/eth/v1/builder/header/:slot/:parent_hash/:pubkey";
pub const GET_HEADER_WITH_PROOFS_PATH: &str =
    "/eth/v1/builder/header_with_proofs/:slot/:parent_hash/:pubkey";
pub const GET_PAYLOAD_PATH: &str = "/eth/v1/builder/blinded_blocks";

#[async_trait::async_trait]
pub trait BuilderApi {
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/status>
    async fn status(&self) -> Result<StatusCode, Box<dyn std::error::Error>>;
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/registerValidator>
    async fn register_validators(
        &self,
        registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), Box<dyn std::error::Error>>;
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/getHeader>
    async fn get_header(
        &self,
        params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, Box<dyn std::error::Error>>;
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock>
    async fn get_payload(
        &self,
        signed_block: SignedBlindedBeaconBlock,
    ) -> Result<Body, Box<dyn std::error::Error>>;
}

#[async_trait::async_trait]
pub trait ConstraintsApi: BuilderApi {
    async fn submit_constraints(
        &self,
        constraints: String,
    ) -> Result<(), Box<dyn std::error::Error>>;

    async fn get_header_with_proofs(
        &self,
        params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, Box<dyn std::error::Error>>;
}
