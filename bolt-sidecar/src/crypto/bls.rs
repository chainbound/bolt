use std::fmt::Debug;

use alloy::{primitives::FixedBytes, rpc::types::beacon::constants::BLS_PUBLIC_KEY_BYTES_LEN};
use blst::{min_pk::Signature, BLST_ERROR};
use ethereum_consensus::{crypto::PublicKey as BlsPublicKey, deneb::compute_signing_root};
use rand::RngCore;

pub use blst::min_pk::{PublicKey, SecretKey as BlsSecretKey};
pub use ethereum_consensus::deneb::BlsSignature;

use crate::{ChainConfig, CommitBoostSigner};

/// The BLS Domain Separator used in Ethereum 2.0.
pub const BLS_DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A fixed-size byte array for BLS signatures.
pub type BLSSig = FixedBytes<96>;

/// Trait for any types that can be signed and verified with BLS.
/// This trait is used to abstract over the signing and verification of different types.
pub trait SignableBLS {
    /// Returns the digest of the object.
    fn digest(&self) -> [u8; 32];
}

/// A generic signing trait to generate BLS signatures.
///
/// Note: we keep this async to allow remote signer implementations.
#[async_trait::async_trait]
pub trait SignerBLS: Send + Debug {
    /// Get the public key of the signer.
    fn pubkey(&self) -> BlsPublicKey;

    /// Sign the given data and return the signature.
    async fn sign_commit_boost_root(&self, data: &[u8; 32]) -> eyre::Result<BLSSig>;
}

pub fn cl_public_key_to_arr(pubkey: BlsPublicKey) -> [u8; BLS_PUBLIC_KEY_BYTES_LEN] {
    pubkey.as_ref().try_into().expect("BLS keys are 48 bytes")
}
