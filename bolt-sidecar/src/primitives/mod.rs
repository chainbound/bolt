// TODO: add docs
#![allow(missing_docs)]

use std::sync::{atomic::AtomicU64, Arc};

use alloy::primitives::U256;
use ethereum_consensus::{
    crypto::KzgCommitment,
    deneb::{
        self,
        mainnet::{BlobsBundle, MAX_BLOB_COMMITMENTS_PER_BLOCK},
        presets::mainnet::ExecutionPayloadHeader,
        Hash32,
    },
    serde::as_str,
    ssz::prelude::*,
    types::mainnet::ExecutionPayload,
    Fork,
};

use tokio::sync::oneshot;

pub use ethereum_consensus::crypto::{PublicKey as BlsPublicKey, Signature as BlsSignature};

/// Commitment types, received by users wishing to receive preconfirmations.
pub mod commitment;
pub use commitment::{CommitmentRequest, InclusionRequest};

/// Constraint types, signed by proposers and sent along the PBS pipeline
/// for validation.
pub mod constraint;
pub use constraint::{BatchedSignedConstraints, ConstraintsMessage, SignedConstraints};

/// Delegation and revocation signed message types and utilities.
pub mod delegation;
pub use delegation::{
    read_signed_delegations_from_file, DelegationMessage, RevocationMessage, SignedDelegation,
    SignedRevocation,
};

/// Transaction types and extension utilities.
pub mod transaction;
pub use transaction::{deserialize_txs, serialize_txs, FullTransaction, TransactionExt};

/// An alias for a Beacon Chain slot number
pub type Slot = u64;

/// Minimal account state needed for commitment validation.
#[derive(Debug, Clone, Copy, Default)]
pub struct AccountState {
    /// The nonce of the account. This is the number of transactions sent from this account
    pub transaction_count: u64,
    /// The balance of the account in wei
    pub balance: U256,
    /// Flag to indicate if the account is a smart contract or an EOA
    pub has_code: bool,
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
    pub response_tx: oneshot::Sender<Option<PayloadAndBid>>,
}

#[derive(Debug)]
pub struct PayloadAndBid {
    pub bid: SignedBuilderBid,
    pub payload: GetPayloadResponse,
}

/// TODO: implement SSZ
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PayloadAndBlobs {
    pub execution_payload: ExecutionPayload,
    pub blobs_bundle: BlobsBundle,
}

impl Default for PayloadAndBlobs {
    fn default() -> Self {
        Self {
            execution_payload: ExecutionPayload::Deneb(deneb::ExecutionPayload::default()),
            blobs_bundle: BlobsBundle::default(),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "version", content = "data")]
pub enum GetPayloadResponse {
    #[serde(rename = "bellatrix")]
    Bellatrix(ExecutionPayload),
    #[serde(rename = "capella")]
    Capella(ExecutionPayload),
    #[serde(rename = "deneb")]
    Deneb(PayloadAndBlobs),
    #[serde(rename = "electra")]
    Electra(PayloadAndBlobs),
}

impl GetPayloadResponse {
    pub fn block_hash(&self) -> &Hash32 {
        match self {
            GetPayloadResponse::Capella(payload) => payload.block_hash(),
            GetPayloadResponse::Bellatrix(payload) => payload.block_hash(),
            GetPayloadResponse::Deneb(payload) => payload.execution_payload.block_hash(),
            GetPayloadResponse::Electra(payload) => payload.execution_payload.block_hash(),
        }
    }

    pub fn execution_payload(&self) -> &ExecutionPayload {
        match self {
            GetPayloadResponse::Capella(payload) => payload,
            GetPayloadResponse::Bellatrix(payload) => payload,
            GetPayloadResponse::Deneb(payload) => &payload.execution_payload,
            GetPayloadResponse::Electra(payload) => &payload.execution_payload,
        }
    }
}

impl From<PayloadAndBlobs> for GetPayloadResponse {
    fn from(payload_and_blobs: PayloadAndBlobs) -> Self {
        match payload_and_blobs.execution_payload.version() {
            Fork::Phase0 => GetPayloadResponse::Capella(payload_and_blobs.execution_payload),
            Fork::Altair => GetPayloadResponse::Capella(payload_and_blobs.execution_payload),
            Fork::Capella => GetPayloadResponse::Capella(payload_and_blobs.execution_payload),
            Fork::Bellatrix => GetPayloadResponse::Bellatrix(payload_and_blobs.execution_payload),
            Fork::Deneb => GetPayloadResponse::Deneb(payload_and_blobs),
            Fork::Electra => GetPayloadResponse::Electra(payload_and_blobs),
        }
    }
}

/// A struct representing the current chain head.
#[derive(Debug, Clone)]
pub struct ChainHead {
    /// The current slot number.
    pub slot: Arc<AtomicU64>,
    /// The current block number.
    pub block: Arc<AtomicU64>,
}

impl ChainHead {
    /// Create a new ChainHead instance.
    pub fn new(slot: u64, block: u64) -> Self {
        Self { slot: Arc::new(AtomicU64::new(slot)), block: Arc::new(AtomicU64::new(block)) }
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
