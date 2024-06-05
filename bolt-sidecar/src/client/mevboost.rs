//! Module for interacting with the MEV-Boost API via its Builder API interface.
//! The Bolt sidecar's main purpose is to sit between the beacon node and MEV-Boost,
//! so most requests are simply proxied to its API.

use axum::{body::Body, http::StatusCode};
use ethereum_consensus::{
    builder::SignedValidatorRegistration, deneb::mainnet::SignedBlindedBeaconBlock,
};
use serde_json::Value;

use crate::{
    api::{
        builder::GetHeaderParams,
        spec::{
            BuilderApi, BuilderApiError, ConstraintsApi, REGISTER_VALIDATORS_PATH, STATUS_PATH,
        },
    },
    types::{constraint::BatchedSignedConstraints, SignedBuilderBid},
};

#[derive(Debug)]
pub struct MevBoostClient {
    url: String,
    client: reqwest::Client,
}

impl MevBoostClient {
    /// Creates a new MEV-Boost client with the given URL.
    pub fn new(url: String) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            client: reqwest::ClientBuilder::new()
                .user_agent("bolt-sidecar")
                .build()
                .unwrap(),
        }
    }

    /// Performs an HTTP POST request to the given endpoint with the given body.
    /// Returns the result of the API request parsed as JSON.
    async fn post_json(
        &self,
        endpoint: &str,
        body: Vec<u8>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let res = self
            .client
            .post(format!("{}/{}", self.url, endpoint))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?
            .json::<Value>()
            .await?;

        Ok(res)
    }

    /// Posts the given signed constraints to the MEV-Boost API.
    pub async fn post_constraints(
        &self,
        constraints: &BatchedSignedConstraints,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let body = serde_json::to_vec(constraints)?;
        self.post_json("/eth/v1/builder/constraints", body).await
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.url, path)
    }
}

#[async_trait::async_trait]
impl BuilderApi for MevBoostClient {
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/status>
    async fn status(&self) -> Result<StatusCode, BuilderApiError> {
        Ok(self
            .client
            .get(self.endpoint(STATUS_PATH))
            .header("content-type", "application/json")
            .send()
            .await?
            .status())
    }

    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/registerValidator>
    async fn register_validators(
        &self,
        registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), BuilderApiError> {
        if self
            .client
            .post(self.endpoint(REGISTER_VALIDATORS_PATH))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&registrations)?)
            .send()
            .await?
            .status()
            != StatusCode::OK
        {
            return Err(BuilderApiError::FailedRegisteringValidators);
        }

        Ok(())
    }

    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/getHeader>
    async fn get_header(
        &self,
        params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, BuilderApiError> {
        // TODO: fix response?
        let response: SignedBuilderBid = self
            .client
            .get(self.endpoint(&format!(
                "/eth/v1/builder/header/{}/{}/{}",
                params.slot, params.parent_hash, params.public_key
            )))
            .header("content-type", "application/json")
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock>
    async fn get_payload(
        &self,
        signed_block: SignedBlindedBeaconBlock,
    ) -> Result<Body, BuilderApiError> {
        todo!()
    }
}

#[async_trait::async_trait]
impl ConstraintsApi for MevBoostClient {
    async fn submit_constraints(&self, constraints: String) -> Result<(), BuilderApiError> {
        todo!()
    }

    async fn get_header_with_proofs(
        &self,
        params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, BuilderApiError> {
        todo!()
    }
}
