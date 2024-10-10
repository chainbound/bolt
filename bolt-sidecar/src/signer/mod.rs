use keystore::KeystoreSigner;
use local::LocalSigner;

use crate::CommitBoostSigner;

pub mod commit_boost;
pub mod keystore;
pub mod local;

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
