use blst::{min_pk::Signature, BLST_ERROR};
use rand::RngCore;

pub use blst::min_pk::PublicKey as BlsPublicKey;
pub use blst::min_pk::SecretKey as BlsSecretKey;
pub use ethereum_consensus::deneb::BlsSignature;

/// The BLS Domain Separator used in Ethereum 2.0.
pub const BLS_DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Trait for any types that can be signed and verified with BLS.
/// This trait is used to abstract over the signing and verification of different types.
pub trait SignableBLS {
    /// Create a digest of the object that can be signed.
    /// This API doesn't enforce a specific hash or encoding method.
    fn digest(&self) -> Vec<u8>;

    /// Sign the object with the given key. Returns the signature.
    ///
    /// Note: The default implementation should be used where possible.
    fn sign(&self, key: &BlsSecretKey) -> Signature {
        key.sign(&self.digest(), BLS_DST_PREFIX, &[])
    }

    /// Verify the signature of the object with the given public key.
    ///
    /// Note: The default implementation should be used where possible.
    fn verify(&self, signature: &Signature, pubkey: &BlsPublicKey) -> bool {
        signature.verify(false, &self.digest(), BLS_DST_PREFIX, &[], pubkey, true)
            == BLST_ERROR::BLST_SUCCESS
    }
}

/// A BLS signer that can sign any type that implements the `Signable` trait.
pub struct BLSSigner {
    key: BlsSecretKey,
}

impl BLSSigner {
    pub fn new(key: BlsSecretKey) -> Self {
        Self { key }
    }

    pub fn sign<T: SignableBLS>(&self, obj: &T) -> Signature {
        obj.sign(&self.key)
    }

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

pub fn from_bls_signature_to_consensus_signature(sig: Signature) -> BlsSignature {
    let bytes = sig.to_bytes();
    BlsSignature::try_from(bytes.as_slice()).unwrap()
}

pub fn random_bls_secret() -> BlsSecretKey {
    let mut rng = rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    BlsSecretKey::key_gen(&ikm, &[]).unwrap()
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::BLSSigner;
    use super::SignableBLS;

    fn test_bls_secret_key() -> SecretKey {
        SecretKey::key_gen(&[0u8; 32], &[]).unwrap()
    }

    struct TestSignableData {
        data: Vec<u8>,
    }

    impl SignableBLS for TestSignableData {
        fn digest(&self) -> Vec<u8> {
            self.data.clone()
        }
    }

    #[test]
    fn test_signer() {
        let key = test_bls_secret_key();
        let pubkey = key.sk_to_pk();
        let signer = BLSSigner::new(key);

        let msg = TestSignableData {
            data: vec![1, 2, 3, 4],
        };

        let signature = signer.sign(&msg);
        assert!(signer.verify(&msg, &signature, &pubkey));
    }
}
