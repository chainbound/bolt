use keystore::KeystoreSigner;
use local::Signer;

use crate::CommitBoostSigner;

pub mod commit_boost;
pub mod keystore;
pub mod local;

#[derive(Clone)]
pub enum SignerBLSEnum {
    Local(Signer),
    CommitBoost(CommitBoostSigner),
    Keystore(KeystoreSigner),
}
