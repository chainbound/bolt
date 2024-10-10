use keystore::KeystoreSigner;
use local::LocalSigner;

use crate::CommitBoostSigner;

pub mod commit_boost;
pub mod keystore;
pub mod local;

#[derive(Clone)]
pub enum SignerBLSEnum {
    Local(LocalSigner),
    CommitBoost(CommitBoostSigner),
    Keystore(KeystoreSigner),
}
