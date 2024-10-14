pub mod commit_boost;
use commit_boost::CommitBoostSigner;

pub mod keystore;
use keystore::KeystoreSigner;

pub mod local;
use local::LocalSigner;

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
