use std::collections::HashSet;

use ethereum_consensus::crypto::bls::PublicKey as BlsPublicKey;

pub mod commit_boost;
use commit_boost::CommitBoostSigner;

pub mod keystore;
use keystore::KeystoreSigner;

pub mod local;
use local::LocalSigner;

/// Error in the signer.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("local signer error: {0}")]
    LocalSigner(#[from] local::LocalSignerError),
    #[error("commit boost signer error: {0}")]
    CommitBoost(#[from] commit_boost::CommitBoostError),
    #[error("keystore signer error: {0}")]
    Keystore(#[from] keystore::KeystoreError),
}

pub type SignerResult<T> = std::result::Result<T, SignerError>;

/// Signer for BLS signatures.
#[derive(Debug, Clone)]
pub enum SignerBLS {
    /// Local signer with a BLS secret key.
    Local(LocalSigner),
    /// Signer from Commit-Boost.
    CommitBoost(CommitBoostSigner),
    /// Signer consisting of multiple keypairs loaded from ERC-2335 keystores files.
    Keystore(KeystoreSigner),
}

impl SignerBLS {
    /// Returns all the public keys available for signing.
    pub fn available_pubkeys(&self) -> HashSet<BlsPublicKey> {
        match self {
            SignerBLS::Local(signer) => [signer.pubkey()].into(),
            SignerBLS::CommitBoost(signer) => [signer.pubkey()].into(),
            SignerBLS::Keystore(signer) => signer.pubkeys(),
        }
    }
}
