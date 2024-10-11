use std::fmt::Debug;

use blst::{min_pk::Signature, BLST_ERROR};
use ethereum_consensus::{crypto::PublicKey as ClPublicKey, deneb::compute_signing_root};

use crate::{crypto::bls::BLSSig, ChainConfig};
pub use blst::min_pk::SecretKey;

/// The BLS Domain Separator used in Ethereum 2.0.
pub const BLS_DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Debug, thiserror::Error)]
pub enum LocalSignerError {
    #[error("Failed to compute signing root: {0}")]
    SigningRootComputation(#[from] ethereum_consensus::error::Error),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
}

type Result<T> = std::result::Result<T, LocalSignerError>;

/// A BLS signer that can sign any type that implements the [`SignableBLS`] trait.
#[derive(Clone)]
pub struct LocalSigner {
    chain: ChainConfig,
    key: SecretKey,
}

impl Debug for LocalSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("pubkey", &self.pubkey())
            .field("chain", &self.chain.name())
            .finish()
    }
}

impl LocalSigner {
    /// Create a new signer with the given BLS secret key.
    pub fn new(key: SecretKey, chain: ChainConfig) -> Self {
        Self { key, chain }
    }

    /// Get the public key of the signer.
    pub fn pubkey(&self) -> ClPublicKey {
        let pk = self.key.sk_to_pk();
        ClPublicKey::try_from(pk.to_bytes().as_ref()).unwrap()
    }

    /// Sign an SSZ object root with the Application Builder domain.
    pub fn sign_application_builder_root(&self, root: [u8; 32]) -> Result<BLSSig> {
        self.sign_root(root, self.chain.application_builder_domain())
    }

    /// Sign an SSZ object root with the Commit Boost domain.
    pub fn sign_commit_boost_root(&self, root: [u8; 32]) -> Result<BLSSig> {
        self.sign_root(root, self.chain.commit_boost_domain())
    }

    /// Sign an SSZ object root with the given domain.
    pub fn sign_root(&self, root: [u8; 32], domain: [u8; 32]) -> Result<BLSSig> {
        let signing_root = compute_signing_root(&root, domain)?;
        let sig = self.key.sign(signing_root.as_slice(), BLS_DST_PREFIX, &[]);
        Ok(BLSSig::from_slice(&sig.to_bytes()))
    }

    /// Verify the signature with the public key of the signer using the Application Builder domain.
    pub fn verify_application_builder_root(
        &self,
        root: [u8; 32],
        signature: &Signature,
    ) -> Result<()> {
        self.verify_root(root, signature, self.chain.application_builder_domain())
    }

    /// Verify the signature with the public key of the signer using the Commit Boost domain.
    pub fn verify_commit_boost_root(&self, root: [u8; 32], signature: &Signature) -> Result<()> {
        self.verify_root(root, signature, self.chain.commit_boost_domain())
    }

    /// Verify the signature of the object with the given public key.
    pub fn verify_root(
        &self,
        root: [u8; 32],
        signature: &Signature,
        domain: [u8; 32],
    ) -> Result<()> {
        let signing_root = compute_signing_root(&root, domain)?;
        let pk = blst::min_pk::PublicKey::from_bytes(self.pubkey().as_ref()).unwrap();

        let res = signature.verify(true, signing_root.as_ref(), BLS_DST_PREFIX, &[], &pk, true);
        if res == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(LocalSignerError::InvalidSignature(format!("{res:?}")))
        }
    }
}

#[cfg(test)]
impl LocalSigner {
    /// Create a signer with a random BLS key configured for Mainnet for testing.
    pub fn random() -> Self {
        use crate::common::BlsSecretKeyWrapper;

        Self { key: BlsSecretKeyWrapper::random().0, chain: ChainConfig::mainnet() }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::bls::SignableBLS, signer::local::LocalSigner, test_util::TestSignableData,
    };

    use rand::Rng;

    #[tokio::test]
    async fn test_bls_signer() {
        let signer = LocalSigner::random();

        // Generate random data for the test
        let mut rng = rand::thread_rng();
        let mut data = [0u8; 32];
        rng.fill(&mut data);
        let msg = TestSignableData { data };

        let signature = signer.sign_commit_boost_root(msg.digest()).unwrap();
        let sig = blst::min_pk::Signature::from_bytes(signature.as_ref()).unwrap();
        assert!(signer.verify_commit_boost_root(msg.digest(), &sig).is_ok());
    }
}
