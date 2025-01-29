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

/// Miscellaneous types and utilities.
pub mod misc;

/// Signature types and utilities.
pub mod signature;

/// JSON-RPC helper types and functions.
pub mod jsonrpc;

/// Types and utilties relates to calculating account diffs.
pub mod diffs;

/// An alias for a Beacon Chain slot number
pub type Slot = u64;

/// Minimal account state needed for commitment validation.
///
/// Each account state is 8 + 32 + 1 + 7 (padding) bytes = 48 bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct AccountState {
    /// The nonce of the account. This is the number of transactions sent from this account
    pub transaction_count: u64,
    /// The balance of the account in wei
    pub balance: U256,
    /// Flag to indicate if the account is a smart contract or an EOA
    pub has_code: bool,
}

/// Builder bid, object that is signed by the proposer
#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
#[allow(missing_docs)]
pub struct BuilderBid {
    pub header: ExecutionPayloadHeader,
    pub blob_kzg_commitments: List<KzgCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    #[serde(with = "as_str")]
    pub value: U256,
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
}

/// Signed builder bid with the proposer signature
#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
#[allow(missing_docs)]
pub struct SignedBuilderBid {
    pub message: BuilderBid,
    pub signature: BlsSignature,
}

/// Signed builder bid with the proposer signature and Bolt inclusion proofs
#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
#[allow(missing_docs)]
pub struct SignedBuilderBidWithProofs {
    pub bid: SignedBuilderBid,
    pub proofs: List<ConstraintProof, 300>,
}

/// A proof that a transaction is included in a block
#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
#[allow(missing_docs)]
pub struct ConstraintProof {
    #[serde(rename = "txHash")]
    tx_hash: Hash32,
    #[serde(rename = "merkleProof")]
    merkle_proof: MerkleProof,
}

/// A merkle proof that a transaction is included in a block.
#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    /// Index of the transaction in the block
    index: u64,
    /// List of hashes that are part of the merkle proof
    hashes: List<Hash32, 1000>,
}

/// Merkle multi-proof that a set of transactions are included in a block
#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct MerkleMultiProof {
    transaction_hashes: List<Hash32, 300>,
    generalized_indexes: List<u64, 300>,
    merkle_hashes: List<Hash32, 1000>,
}

/// Request to fetch a payload for a given slot
#[derive(Debug)]
pub struct FetchPayloadRequest {
    /// Slot number for the payload to fetch
    pub slot: u64,
    /// Channel to send the response to
    pub response_tx: oneshot::Sender<Option<PayloadAndBid>>,
}

/// Response to a fetch payload request
#[derive(Debug)]
#[allow(missing_docs)]
pub struct PayloadAndBid {
    pub bid: SignedBuilderBid,
    pub payload: GetPayloadResponse,
}

/// GetPayload response content, with blobs bundle included.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(missing_docs)]
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

/// Response to a get payload request
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "version", content = "data")]
#[allow(missing_docs)]
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
    /// Returns the block hash of the payload
    pub fn block_hash(&self) -> &Hash32 {
        match self {
            Self::Capella(payload) | Self::Bellatrix(payload) => payload.block_hash(),
            Self::Deneb(payload) | Self::Electra(payload) => payload.execution_payload.block_hash(),
        }
    }

    /// Returns the execution payload
    pub fn execution_payload(&self) -> &ExecutionPayload {
        match self {
            Self::Capella(payload) | Self::Bellatrix(payload) => payload,
            Self::Deneb(payload) | Self::Electra(payload) => &payload.execution_payload,
        }
    }
}

impl From<PayloadAndBlobs> for GetPayloadResponse {
    fn from(payload_and_blobs: PayloadAndBlobs) -> Self {
        match payload_and_blobs.execution_payload.version() {
            Fork::Phase0 | Fork::Altair | Fork::Capella => {
                Self::Capella(payload_and_blobs.execution_payload)
            }
            Fork::Bellatrix => Self::Bellatrix(payload_and_blobs.execution_payload),
            Fork::Deneb => Self::Deneb(payload_and_blobs),
            Fork::Electra => Self::Electra(payload_and_blobs),
        }
    }
}
