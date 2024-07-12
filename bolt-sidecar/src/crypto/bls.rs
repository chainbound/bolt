use alloy_primitives::FixedBytes;
use blst::{min_pk::Signature, BLST_ERROR};
use rand::RngCore;

pub use blst::min_pk::PublicKey as BlsPublicKey;
pub use blst::min_pk::SecretKey as BlsSecretKey;
pub use ethereum_consensus::deneb::BlsSignature;

/// The BLS Domain Separator used in Ethereum 2.0.
pub const BLS_DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A fixed-size byte array for BLS signatures.
pub type BLSBytes = FixedBytes<96>;

/// Trait for any types that can be signed and verified with BLS.
/// This trait is used to abstract over the signing and verification of different types.
pub trait SignableBLS {
    /// Create a digest of the object that can be signed.
    /// This API doesn't enforce a specific hash or encoding method.
    fn digest(&self) -> Vec<u8>;

    /// Sign the object with the given key. Returns the signature.
    ///
    /// Note: The default implementation should be used where possible.
    #[allow(dead_code)]
    fn sign(&self, key: &BlsSecretKey) -> Signature {
        sign_with_prefix(key, &self.digest())
    }

    /// Verify the signature of the object with the given public key.
    ///
    /// Note: The default implementation should be used where possible.
    fn verify(&self, signature: &Signature, pubkey: &BlsPublicKey) -> bool {
        signature.verify(false, &self.digest(), BLS_DST_PREFIX, &[], pubkey, true)
            == BLST_ERROR::BLST_SUCCESS
    }
}

/// A generic signing trait to generate BLS signatures.
#[allow(dead_code)]
pub trait SignerBLS {
    /// Sign the given data and return the signature.
    fn sign(&self, data: &[u8]) -> eyre::Result<BLSBytes>;
}

/// A generic signing trait to generate BLS signatures asynchronously.
#[async_trait::async_trait]
pub trait SignerBLSAsync: Send + Sync {
    /// Sign the given data and return the signature.
    async fn sign(&self, data: &[u8]) -> eyre::Result<BLSBytes>;
}

/// A BLS signer that can sign any type that implements the `Signable` trait.
#[derive(Debug, Clone)]
pub struct Signer {
    key: BlsSecretKey,
}

impl Signer {
    /// Create a new signer with the given BLS secret key.
    pub fn new(key: BlsSecretKey) -> Self {
        Self { key }
    }

    /// Create a signer with a random BLS key.
    pub fn random() -> Self {
        Self {
            key: random_bls_secret(),
        }
    }

    /// Verify the signature of the object with the given public key.
    #[allow(dead_code)]
    pub fn verify<T: SignableBLS>(
        &self,
        obj: &T,
        signature: &Signature,
        pubkey: &BlsPublicKey,
    ) -> bool {
        obj.verify(signature, pubkey)
    }
}

impl SignerBLS for Signer {
    fn sign(&self, data: &[u8]) -> eyre::Result<BLSBytes> {
        let sig = sign_with_prefix(&self.key, data);
        Ok(BLSBytes::from(sig.to_bytes()))
    }
}

#[async_trait::async_trait]
impl SignerBLSAsync for Signer {
    async fn sign(&self, data: &[u8]) -> eyre::Result<BLSBytes> {
        let sig = sign_with_prefix(&self.key, data);
        Ok(BLSBytes::from(sig.to_bytes()))
    }
}

/// Compatibility between ethereum_consensus and blst
pub fn from_bls_signature_to_consensus_signature(sig_bytes: impl AsRef<[u8]>) -> BlsSignature {
    BlsSignature::try_from(sig_bytes.as_ref()).unwrap()
}

/// Generate a random BLS secret key.
pub fn random_bls_secret() -> BlsSecretKey {
    let mut rng = rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    BlsSecretKey::key_gen(&ikm, &[]).unwrap()
}

/// Sign the given data with the given BLS secret key.
#[inline]
fn sign_with_prefix(key: &BlsSecretKey, data: &[u8]) -> Signature {
    key.sign(data, BLS_DST_PREFIX, &[])
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::bls::{SignableBLS, Signer, SignerBLS},
        test_util::{test_bls_secret_key, TestSignableData},
    };

    #[test]
    fn test_bls_signer() {
        let key = test_bls_secret_key();
        let pubkey = key.sk_to_pk();
        let signer = Signer::new(key);

        let msg = TestSignableData {
            data: vec![1, 2, 3, 4],
        };

        let signature = SignerBLS::sign(&signer, &msg.digest()).unwrap();
        let sig = blst::min_pk::Signature::from_bytes(signature.as_ref()).unwrap();
        assert!(signer.verify(&msg, &sig, &pubkey));
    }
}
