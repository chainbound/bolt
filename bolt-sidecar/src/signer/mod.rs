pub mod commit_boost;
use commit_boost::CommitBoostSigner;

pub mod keystore;
use keystore::KeystoreSigner;

pub mod local;
use local::LocalSigner;

#[derive(Debug, Clone)]
/// Signer for BLS signatures.
pub enum SignerBLS {
    /// Local signer with a BLS secret key.
    Local(LocalSigner),
    /// Signer from Commit-Boost.
    CommitBoost(CommitBoostSigner),
    /// Signer consisting of multiple keypairs loaded from ERC-2335 keystores files.
    Keystore(KeystoreSigner),
}
