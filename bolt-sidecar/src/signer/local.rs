use std::fmt::Debug;

use blst::{min_pk::Signature, BLST_ERROR};
use ethereum_consensus::{crypto::PublicKey as BlsPublicKey, deneb::compute_signing_root};
use rand::RngCore;

use crate::{crypto::bls::BLSSig, ChainConfig};
pub use blst::min_pk::SecretKey as BlsSecretKey;

/// The BLS Domain Separator used in Ethereum 2.0.
pub const BLS_DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A BLS signer that can sign any type that implements the [`SignableBLS`] trait.
#[derive(Clone)]
pub struct LocalSigner {
    chain: ChainConfig,
    key: BlsSecretKey,
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
    pub fn new(key: BlsSecretKey, chain: ChainConfig) -> Self {
        Self { key, chain }
    }

    /// Create a signer with a random BLS key configured for Mainnet for testing.
    #[cfg(test)]
    pub fn random() -> Self {
        Self { key: random_bls_secret(), chain: ChainConfig::mainnet() }
    }

    /// Get the public key of the signer.
    pub fn pubkey(&self) -> BlsPublicKey {
        let pk = self.key.sk_to_pk();
        BlsPublicKey::try_from(pk.to_bytes().as_ref()).unwrap()
    }

    /// Sign an SSZ object root with the Application Builder domain.
    pub fn sign_application_builder_root(&self, root: [u8; 32]) -> eyre::Result<BLSSig> {
        self.sign_root(root, self.chain.application_builder_domain())
    }

    /// Sign an SSZ object root with the Commit Boost domain.
    pub fn sign_commit_boost_root(&self, root: [u8; 32]) -> eyre::Result<BLSSig> {
        self.sign_root(root, self.chain.commit_boost_domain())
    }

    /// Sign an SSZ object root with the given domain.
    pub fn sign_root(&self, root: [u8; 32], domain: [u8; 32]) -> eyre::Result<BLSSig> {
        let signing_root = compute_signing_root(&root, domain)?;
        let sig = self.key.sign(signing_root.as_slice(), BLS_DST_PREFIX, &[]);
        Ok(BLSSig::from_slice(&sig.to_bytes()))
    }

    /// Verify the signature with the public key of the signer using the Application Builder domain.
    pub fn verify_application_builder_root(
        &self,
        root: [u8; 32],
        signature: &Signature,
    ) -> eyre::Result<()> {
        self.verify_root(root, signature, self.chain.application_builder_domain())
    }

    /// Verify the signature with the public key of the signer using the Commit Boost domain.
    pub fn verify_commit_boost_root(
        &self,
        root: [u8; 32],
        signature: &Signature,
    ) -> eyre::Result<()> {
        self.verify_root(root, signature, self.chain.commit_boost_domain())
    }

    /// Verify the signature of the object with the given public key.
    pub fn verify_root(
        &self,
        root: [u8; 32],
        signature: &Signature,
        domain: [u8; 32],
    ) -> eyre::Result<()> {
        let signing_root = compute_signing_root(&root, domain)?;
        let pk = blst::min_pk::PublicKey::from_bytes(self.pubkey().as_ref()).unwrap();

        let res = signature.verify(true, signing_root.as_ref(), BLS_DST_PREFIX, &[], &pk, true);
        if res == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            eyre::bail!(format!("Invalid signature: {:?}", res))
        }
    }
}

/// Generate a random BLS secret key.
pub fn random_bls_secret() -> BlsSecretKey {
    let mut rng = rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    BlsSecretKey::key_gen(&ikm, &[]).unwrap()
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
