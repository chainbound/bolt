//! Module for interacting with the MEV-Boost API via its Builder API interface.
//! The Bolt sidecar's main purpose is to sit between the beacon node and MEV-Boost,
//! so most requests are simply proxied to its API.

use eyre::Context;
use serde_json::Value;

use super::{api::JsonApiResult, types::BatchedSignedConstraints};

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
    async fn post_json(&self, endpoint: &str, body: Vec<u8>) -> JsonApiResult {
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
    pub async fn post_constraints(&self, constraints: &BatchedSignedConstraints) -> JsonApiResult {
        let body = serde_json::to_vec(constraints)?;
        self.post_json("/eth/v1/builder/constraints", body).await
    }
}
