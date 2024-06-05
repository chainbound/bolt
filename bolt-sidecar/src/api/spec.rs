use axum::{body::Body, http::StatusCode};
use ethereum_consensus::{
    builder::SignedValidatorRegistration, deneb::mainnet::SignedBlindedBeaconBlock,
};

use crate::types::SignedBuilderBid;

use super::builder::GetHeaderParams;

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
}
