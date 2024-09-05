use alloy::{
    consensus::TxEnvelope,
    eips::eip2718::{Decodable2718, Eip2718Error},
    primitives::{Bytes, TxHash, B256},
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
};
use axum::http::HeaderMap;
use commit_boost::prelude::tree_hash::{self, MerkleHasher, TreeHash, TreeHashType};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::ops::Deref;

use cb_common::{
    constants::COMMIT_BOOST_DOMAIN,
    pbs::{DenebSpec, EthSpec, SignedExecutionPayloadHeader, Transaction, VersionedResponse},
    signature::verify_signed_message,
    types::Chain,
};

/// A hash tree root.
pub type HashTreeRoot = tree_hash::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct GetHeaderParams {
    pub slot: u64,
    pub parent_hash: B256,
    pub pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedConstraints {
    pub message: ConstraintsMessage,
    pub signature: BlsSignature,
}

impl SignedConstraints {
    /// Verifies the signature on this message against the provided BLS public key.
    /// The `chain` and `COMMIT_BOOST_DOMAIN` are used to compute the signing root.
    #[allow(unused)]
    pub fn verify_signature(&self, chain: Chain, pubkey: &BlsPublicKey) -> bool {
        verify_signed_message(
            chain,
            pubkey,
            &self.message,
            &self.signature,
            COMMIT_BOOST_DOMAIN,
        )
        .is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq, Deserialize, Encode, Decode)]
pub struct ConstraintsMessage {
    pub validator_index: u64,
    pub slot: u64,
    pub top: bool,
    pub transactions: Vec<Bytes>,
}

impl ConstraintsMessage {
    /// Returns the total number of leaves in the tree.
    fn total_leaves(&self) -> usize {
        4 + self.transactions.len()
    }
}

impl TreeHash for ConstraintsMessage {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("ConstraintsMessage should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("ConstraintsMessage should never be packed.")
    }

    fn tree_hash_root(&self) -> HashTreeRoot {
        let mut hasher = MerkleHasher::with_leaves(self.total_leaves());

        hasher
            .write(&self.validator_index.to_le_bytes())
            .expect("Should write validator index bytes");
        hasher
            .write(&self.slot.to_le_bytes())
            .expect("Should write slot bytes");
        hasher
            .write(&(self.top as u8).to_le_bytes())
            .expect("Should write top flag");

        for transaction in &self.transactions {
            hasher
                .write(
                    Transaction::<<DenebSpec as EthSpec>::MaxBytesPerTransaction>::from(
                        transaction.to_vec(),
                    )
                    .tree_hash_root()
                    .as_bytes(),
                )
                .expect("Should write transaction root");
        }

        hasher.finish().unwrap()
    }
}

#[derive(Debug)]
pub struct ConstraintsWithProofData {
    pub message: ConstraintsMessage,
    /// List of transaction hashes and corresponding hash tree roots. Same order
    /// as the transactions in the `message`.
    pub proof_data: Vec<(TxHash, HashTreeRoot)>,
}

impl TryFrom<ConstraintsMessage> for ConstraintsWithProofData {
    type Error = Eip2718Error;

    fn try_from(value: ConstraintsMessage) -> Result<Self, Self::Error> {
        let transactions = value
            .transactions
            .iter()
            .map(|tx| {
                let tx_hash = *TxEnvelope::decode_2718(&mut tx.as_ref())?.tx_hash();

                let tx_root =
                    tree_hash::TreeHash::tree_hash_root(&Transaction::<
                        <DenebSpec as EthSpec>::MaxBytesPerTransaction,
                    >::from(tx.to_vec()));

                Ok((tx_hash, tx_root))
            })
            .collect::<Result<Vec<_>, Eip2718Error>>()?;

        Ok(Self {
            message: value,
            proof_data: transactions,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct DelegationMessage {
    pub validator_index: u64,
    pub pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedRevocation {
    pub message: RevocationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct RevocationMessage {
    pub validator_index: u64,
    pub pubkey: BlsPublicKey,
}

pub type GetHeaderWithProofsResponse = VersionedResponse<SignedExecutionPayloadHeaderWithProofs>;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedExecutionPayloadHeaderWithProofs {
    #[serde(flatten)]
    pub header: SignedExecutionPayloadHeader,
    pub proofs: InclusionProofs,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct InclusionProofs {
    /// The transaction hashes these inclusion proofs are for. The hash tree roots of
    /// these transactions are the leaves of the transactions tree.
    pub transaction_hashes: Vec<TxHash>,
    /// The generalized indeces of the nodes in the transactions tree.
    pub generalized_indeces: Vec<usize>,
    /// The proof hashes for the transactions tree.
    pub merkle_hashes: Vec<B256>,
}

impl InclusionProofs {
    /// Returns the total number of leaves in the tree.
    pub fn total_leaves(&self) -> usize {
        self.transaction_hashes.len()
    }
}

impl Deref for SignedExecutionPayloadHeaderWithProofs {
    type Target = SignedExecutionPayloadHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

#[derive(Debug)]
pub struct RequestConfig {
    pub url: Url,
    pub timeout_ms: u64,
    pub headers: HeaderMap,
}
