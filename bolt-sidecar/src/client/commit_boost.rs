use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use cb_common::pbs::{COMMIT_BOOST_API, PUBKEYS_PATH, SIGN_REQUEST_PATH};
use cb_crypto::types::SignRequest;
use ethereum_consensus::ssz::prelude::HashTreeRoot;
use reqwest::{IntoUrl, Url};
use thiserror::Error;

use crate::primitives::ConstraintsMessage;

const id: &str = "bolt";

pub struct CommitBoostClient {
    url: Url,
    client: reqwest::Client,
    pubkeys: Vec<BlsPublicKey>,
}

#[derive(Debug, Error)]
pub enum CommitBoostError {
    #[error("Failed to get public keys")]
    FailedGettingPubkeys,
    #[error("Bad url")]
    BadUrl,
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

impl CommitBoostClient {
    pub async fn new(url: impl IntoUrl) -> Result<Self, CommitBoostError> {
        let mut client = Self {
            url: url.into_url().map_err(|_| CommitBoostError::BadUrl)?,
            client: reqwest::Client::new(),
            pubkeys: Vec::new(),
        };

        client.load_pubkeys().await?;

        Ok(client)
    }

    async fn load_pubkeys(&mut self) -> Result<(), CommitBoostError> {
        let url = format!("{}{COMMIT_BOOST_API}{PUBKEYS_PATH}", self.url);

        tracing::debug!(url, "Loading signatures from commit_boost");

        let response = self.client.get(url).send().await?;
        let status = response.status();
        let response_bytes = response.bytes().await.expect("failed to get bytes");

        if !status.is_success() {
            let err = String::from_utf8_lossy(&response_bytes).into_owned();
            tracing::error!(err, ?status, "failed to get public keys");
            return Err(CommitBoostError::FailedGettingPubkeys);
        }

        let pubkeys: Vec<BlsPublicKey> =
            serde_json::from_slice(&response_bytes).expect("failed deser");

        self.pubkeys = pubkeys;
        Ok(())
    }

    // TODO: error handling
    pub async fn sign_constraint(&self, constraint: &ConstraintsMessage) -> Option<BlsSignature> {
        let root = constraint.hash_tree_root().unwrap();
        let request = SignRequest::builder(id, *self.pubkeys.first().expect("pubkeys loaded"))
            .with_root(root.into());

        let url = format!("{}{COMMIT_BOOST_API}{SIGN_REQUEST_PATH}", self.url);

        tracing::debug!(url, ?request, "Requesting signature from commit_boost");

        let response = reqwest::Client::new()
            .post(url)
            .json(&request)
            .send()
            .await
            .expect("failed to get request");

        let status = response.status();
        let response_bytes = response.bytes().await.expect("failed to get bytes");

        if !status.is_success() {
            let err = String::from_utf8_lossy(&response_bytes).into_owned();
            tracing::error!(err, "failed to get signature");
            return None;
        }

        serde_json::from_slice(&response_bytes).expect("failed deser")
    }
}
