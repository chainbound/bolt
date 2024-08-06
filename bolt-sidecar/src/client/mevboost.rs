//! Module for interacting with the MEV-Boost API via its Builder API interface.
//! The Bolt sidecar's main purpose is to sit between the beacon node and MEV-Boost,
//! so most requests are simply proxied to its API.

use axum::http::StatusCode;
use beacon_api_client::VersionedValue;
use ethereum_consensus::{
    builder::SignedValidatorRegistration, deneb::mainnet::SignedBlindedBeaconBlock, Fork,
};
use reqwest::Url;

use crate::{
    api::{
        builder::GetHeaderParams,
        spec::{
            BuilderApi, BuilderApiError, ConstraintsApi, ErrorResponse, CONSTRAINTS_PATH,
            GET_PAYLOAD_PATH, REGISTER_VALIDATORS_PATH, STATUS_PATH,
        },
    },
    primitives::{BatchedSignedConstraints, GetPayloadResponse, SignedBuilderBid},
};

/// A client for interacting with the MEV-Boost API.
#[derive(Debug, Clone)]
pub struct MevBoostClient {
    url: Url,
    client: reqwest::Client,
}

impl MevBoostClient {
    /// Creates a new MEV-Boost client with the given URL.
    pub fn new<U: Into<Url>>(url: U) -> Self {
        Self {
            url: url.into(),
            client: reqwest::ClientBuilder::new().user_agent("bolt-sidecar").build().unwrap(),
        }
    }

    fn endpoint(&self, path: &str) -> Url {
        self.url.join(path).unwrap_or_else(|e| {
            tracing::error!(err = ?e, "Failed to join path: {} with url: {}", path, self.url);
            self.url.clone()
        })
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
        let response = self
            .client
            .post(self.endpoint(REGISTER_VALIDATORS_PATH))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&registrations)?)
            .send()
            .await?;

        if response.status() != StatusCode::OK {
            let error = response.json::<ErrorResponse>().await?;
            return Err(BuilderApiError::FailedRegisteringValidators(error));
        }

        Ok(())
    }

    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/getHeader>
    async fn get_header(
        &self,
        params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, BuilderApiError> {
        let parent_hash = format!("0x{}", hex::encode(params.parent_hash.as_ref()));
        let public_key = format!("0x{}", hex::encode(params.public_key.as_ref()));

        let response = self
            .client
            .get(self.endpoint(&format!(
                "/eth/v1/builder/header/{}/{}/{}",
                params.slot, parent_hash, public_key
            )))
            .header("content-type", "application/json")
            .send()
            .await?;

        if response.status() != StatusCode::OK {
            let error = response.json::<ErrorResponse>().await?;
            return Err(BuilderApiError::FailedGettingHeader(error));
        }

        let header = response.json::<SignedBuilderBid>().await?;

        Ok(header)
    }

    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock>
    async fn get_payload(
        &self,
        signed_block: SignedBlindedBeaconBlock,
    ) -> Result<GetPayloadResponse, BuilderApiError> {
        let response = self
            .client
            .post(self.endpoint(GET_PAYLOAD_PATH))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&signed_block)?)
            .send()
            .await?;

        if response.status() != StatusCode::OK {
            let error = response.json::<ErrorResponse>().await?;
            return Err(BuilderApiError::FailedGettingPayload(error));
        }

        let payload = response.json().await?;

        Ok(payload)
    }
}

#[async_trait::async_trait]
impl ConstraintsApi for MevBoostClient {
    async fn submit_constraints(
        &self,
        constraints: &BatchedSignedConstraints,
    ) -> Result<(), BuilderApiError> {
        let response = self
            .client
            .post(self.endpoint(CONSTRAINTS_PATH))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&constraints)?)
            .send()
            .await?;

        if response.status() != StatusCode::OK {
            let error = response.json::<ErrorResponse>().await?;
            return Err(BuilderApiError::FailedSubmittingConstraints(error));
        }

        Ok(())
    }

    async fn get_header_with_proofs(
        &self,
        params: GetHeaderParams,
    ) -> Result<VersionedValue<SignedBuilderBid>, BuilderApiError> {
        let parent_hash = format!("0x{}", hex::encode(params.parent_hash.as_ref()));
        let public_key = format!("0x{}", hex::encode(params.public_key.as_ref()));

        let response = self
            .client
            .get(self.endpoint(&format!(
                "/eth/v1/builder/header_with_proofs/{}/{}/{}",
                params.slot, parent_hash, public_key,
            )))
            .header("content-type", "application/json")
            .send()
            .await?;

        if response.status() != StatusCode::OK {
            let error = response.json::<ErrorResponse>().await?;
            return Err(BuilderApiError::FailedGettingHeader(error));
        }

        let header = response.json::<VersionedValue<SignedBuilderBid>>().await?;

        if !matches!(header.version, Fork::Deneb) {
            return Err(BuilderApiError::InvalidFork(header.version.to_string()));
        };

        // TODO: verify proofs here?

        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use reqwest::Url;

    use crate::MevBoostClient;

    #[test]
    fn test_join_endpoints() {
        let client = MevBoostClient::new(Url::parse("http://localhost:8080/").unwrap());
        assert_eq!(
            client.endpoint("/eth/v1/builder/header/1/0x123/0x456"),
            Url::parse("http://localhost:8080/eth/v1/builder/header/1/0x123/0x456").unwrap()
        );

        assert_eq!(
            client.endpoint("eth/v1/builder/validators"),
            Url::parse("http://localhost:8080/eth/v1/builder/validators").unwrap()
        );
    }
}
