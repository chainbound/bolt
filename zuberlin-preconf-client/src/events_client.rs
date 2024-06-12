use serde::{Deserialize, Serialize};

use crate::Error;

const PRECONF_REQUESTED_PATH: &str = "/events/preconfs/requested";
const PRECONF_RESPONDED_PATH: &str = "/events/preconfs/responded";
const PRECONF_CONFIRMED_PATH: &str = "/events/preconfs/confirmed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconfRequestedEvent {
    /// Bolt or titan
    pub protocol_id: String,
    /// The transaction hash
    pub tx_hash: String,
    /// Timestamp in UNIX milliseconds
    pub timestamp: u64,
    /// The target slot
    pub slot: u64,
    /// The target validator index
    pub validator_index: u64,
    /// Preconf endpoint
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconfRespondedEvent {
    /// Bolt or titan
    pub protocol_id: String,
    /// The transaction hash
    pub tx_hash: String,
    /// Timestamp in UNIX milliseconds
    pub timestamp: u64,
    /// The target slot
    pub slot: u64,
    /// The target validator index
    pub validator_index: u64,
    /// Preconf endpoint
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconfsConfirmedEvent {
    /// Bolt or titan
    pub protocol_id: String,
    /// Timestamp in UNIX milliseconds
    pub timestamp: u64,
    /// The target slot
    pub slot: u64,
    /// The block number
    pub block_number: u64,
    /// The block hash
    pub block_hash: String,
    /// The block graffiti (to identify the builder)
    pub graffiti: String,
    /// The target validator index
    pub validator_index: u64,
    /// Preconf endpoint
    pub endpoint: String,
    /// The transaction hashes that were confirmed
    pub tx_hashes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EventsClient {
    url: String,
    client: reqwest::Client,
}

impl EventsClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    // Can do this on a per-request basis
    pub async fn preconf_requested(&self, event: PreconfRequestedEvent) -> Result<(), Error> {
        let path = format!("{}{}", self.url, PRECONF_REQUESTED_PATH);

        let response = self
            .client
            .post(path)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&event)?)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::RequestFailed(response.status().as_u16()));
        }

        Ok(())
    }

    // Can do this on a per-request basis
    pub async fn preconf_responded(&self, event: PreconfRespondedEvent) -> Result<(), Error> {
        let path = format!("{}{}", self.url, PRECONF_RESPONDED_PATH);

        let response = self
            .client
            .post(path)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&event)?)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::RequestFailed(response.status().as_u16()));
        }

        Ok(())
    }

    // Can be multiple (per block)
    pub async fn preconfs_confirmed(&self, event: PreconfsConfirmedEvent) -> Result<(), Error> {
        let path = format!("{}{}", self.url, PRECONF_CONFIRMED_PATH);

        let response = self
            .client
            .post(path)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&event)?)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::RequestFailed(response.status().as_u16()));
        }

        Ok(())
    }
}
