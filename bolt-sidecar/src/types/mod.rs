use alloy_primitives::U256;
use axum::body::Body;
use ethereum_consensus::{
    capella,
    crypto::KzgCommitment,
    deneb::mainnet::{BlobsBundle, ExecutionPayloadHeader, MAX_BLOB_COMMITMENTS_PER_BLOCK},
    primitives::{BlsPublicKey, BlsSignature},
    serde::as_str,
    ssz::prelude::*,
    types::mainnet::ExecutionPayload,
    Fork,
};
use tokio::sync::{mpsc, oneshot};

pub mod commitment;
pub mod constraint;
pub mod transaction;

/// An alias for a Beacon Chain slot number
pub type Slot = u64;

/// Minimal account state needed for commitment validation.
#[derive(Debug, Clone, Copy)]
pub struct AccountState {
    /// The nonce of the account. This is the number of transactions sent from this account
    /// and should be the
    pub transaction_count: u64,
    pub balance: U256,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct BuilderBid {
    pub header: ExecutionPayloadHeader,
    pub blob_kzg_commitments: List<KzgCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    #[serde(with = "as_str")]
    pub value: U256,
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SignedBuilderBid {
    pub message: BuilderBid,
    pub signature: BlsSignature,
}

pub struct FetchPayloadRequest {
    pub slot: u64,
    pub response: oneshot::Sender<Option<PayloadAndBid>>,
}

pub struct PayloadAndBid {
    pub bid: SignedBuilderBid,
    pub payload: Body,
}

pub struct LocalPayloadFetcher {
    tx: mpsc::Sender<FetchPayloadRequest>,
}

#[async_trait::async_trait]
impl PayloadFetcher for LocalPayloadFetcher {
    async fn fetch_payload(&self, slot: u64) -> Option<PayloadAndBid> {
        let (tx, rx) = oneshot::channel();

        let fetch_params = FetchPayloadRequest { slot, response: tx };

        self.tx.send(fetch_params).await.ok()?;

        rx.await.ok().flatten()
    }
}

#[async_trait::async_trait]
pub trait PayloadFetcher {
    async fn fetch_payload(&self, slot: u64) -> Option<PayloadAndBid>;
}

pub struct NoopPayloadFetcher;

#[async_trait::async_trait]
impl PayloadFetcher for NoopPayloadFetcher {
    async fn fetch_payload(&self, slot: u64) -> Option<PayloadAndBid> {
        tracing::info!(slot, "Fetch payload called");
        None
    }
}

/// TODO: implement SSZ
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PayloadAndBlobs {
    pub execution_payload: ExecutionPayload,
    pub blobs_bundle: Option<BlobsBundle>,
}

impl Default for PayloadAndBlobs {
    fn default() -> Self {
        Self {
            execution_payload: ExecutionPayload::Capella(capella::ExecutionPayload::default()),
            blobs_bundle: None,
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "version", content = "data")]
pub enum GetPayloadResponse {
    #[serde(rename = "bellatrix")]
    Bellatrix(ExecutionPayload),
    #[serde(rename = "capella")]
    Capella(ExecutionPayload),
    #[serde(rename = "deneb")]
    Deneb(PayloadAndBlobs),
}

impl GetPayloadResponse {
    pub fn try_from_execution_payload(exec_payload: &PayloadAndBlobs) -> Option<Self> {
        match exec_payload.execution_payload.version() {
            Fork::Capella => Some(GetPayloadResponse::Capella(
                exec_payload.execution_payload.clone(),
            )),
            Fork::Bellatrix => Some(GetPayloadResponse::Bellatrix(
                exec_payload.execution_payload.clone(),
            )),
            Fork::Deneb => Some(GetPayloadResponse::Deneb(exec_payload.clone())),
            _ => None,
        }
    }
}

impl<'de> serde::Deserialize<'de> for GetPayloadResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Capella(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Deneb(inner));
        }
        if let Ok(inner) = <_ as serde::Deserialize>::deserialize(&value) {
            return Ok(Self::Bellatrix(inner));
        }
        Err(serde::de::Error::custom(
            "no variant could be deserialized from input for GetPayloadResponse",
        ))
    }
}
