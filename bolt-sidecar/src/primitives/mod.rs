// TODO: add docs
#![allow(missing_docs)]

use std::sync::{atomic::AtomicU64, Arc};

use alloy_primitives::U256;
use ethereum_consensus::{
    capella,
    crypto::{KzgCommitment, PublicKey as BlsPublicKey, Signature as BlsSignature},
    deneb::{
        mainnet::{BlobsBundle, MAX_BLOB_COMMITMENTS_PER_BLOCK},
        presets::mainnet::ExecutionPayloadHeader,
        Hash32,
    },
    serde::as_str,
    ssz::prelude::*,
    types::mainnet::ExecutionPayload,
    Fork,
};
use tokio::sync::{mpsc, oneshot};

/// Commitment types, received by users wishing to receive preconfirmations.
pub mod commitment;
pub use commitment::{CommitmentRequest, InclusionRequest};

/// Constraint types, signed by proposers and sent along the PBS pipeline
/// for validation.
pub mod constraint;
pub use constraint::{BatchedSignedConstraints, ConstraintsMessage, SignedConstraints};

/// Transaction primitives and utilities.
pub mod transaction;
pub use transaction::TxInfo;

/// An alias for a Beacon Chain slot number
pub type Slot = u64;

/// Minimal account state needed for commitment validation.
#[derive(Debug, Clone, Copy)]
pub struct AccountState {
    /// The nonce of the account. This is the number of transactions sent from this account
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

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SignedBuilderBidWithProofs {
    pub bid: SignedBuilderBid,
    pub proofs: List<ConstraintProof, 300>,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct ConstraintProof {
    #[serde(rename = "txHash")]
    tx_hash: Hash32,
    #[serde(rename = "merkleProof")]
    merkle_proof: MerkleProof,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    index: u64,
    // TODO: for now, max 1000
    hashes: List<Hash32, 1000>,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct MerkleMultiProof {
    // We use List here for SSZ, TODO: choose max
    transaction_hashes: List<Hash32, 300>,
    generalized_indexes: List<u64, 300>,
    merkle_hashes: List<Hash32, 1000>,
}

#[derive(Debug)]
pub struct FetchPayloadRequest {
    pub slot: u64,
    pub response: oneshot::Sender<Option<PayloadAndBid>>,
}

#[derive(Debug)]
pub struct PayloadAndBid {
    pub bid: SignedBuilderBid,
    pub payload: GetPayloadResponse,
}

#[derive(Debug, Clone)]
pub struct LocalPayloadFetcher {
    tx: mpsc::Sender<FetchPayloadRequest>,
}

impl LocalPayloadFetcher {
    pub fn new(tx: mpsc::Sender<FetchPayloadRequest>) -> Self {
        Self { tx }
    }
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

#[derive(Debug)]
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

/// A struct representing the current chain head.
#[derive(Debug, Clone)]
pub struct ChainHead {
    /// The current slot number.
    slot: Arc<AtomicU64>,
    /// The current block number.
    block: Arc<AtomicU64>,
}

impl ChainHead {
    /// Create a new ChainHead instance.
    pub fn new(slot: u64, head: u64) -> Self {
        Self {
            slot: Arc::new(AtomicU64::new(slot)),
            block: Arc::new(AtomicU64::new(head)),
        }
    }

    /// Get the slot number (consensus layer).
    pub fn slot(&self) -> u64 {
        self.slot.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get the block number (execution layer).
    pub fn block(&self) -> u64 {
        self.block.load(std::sync::atomic::Ordering::SeqCst)
    }
}
