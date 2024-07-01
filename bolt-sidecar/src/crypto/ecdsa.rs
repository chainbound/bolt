use secp256k1::{ecdsa::Signature, Message, PublicKey, SecretKey};

/// Trait for any types that can be signed and verified with ECDSA.
/// This trait is used to abstract over the signing and verification of different types.
pub trait SignableECDSA {
    /// Create a digest of the object that can be signed.
    /// This API doesn't enforce a specific hash or encoding method.
    fn digest(&self) -> Message;

    /// Sign the object with the given key. Returns the signature.
    ///
    /// Note: The default implementation should be used where possible.
    fn sign(&self, key: &SecretKey) -> Signature {
        secp256k1::Secp256k1::new().sign_ecdsa(&self.digest(), key)
    }

    /// Verify the signature of the object with the given public key.
    ///
    /// Note: The default implementation should be used where possible.
    fn verify(&self, signature: &Signature, pubkey: &PublicKey) -> bool {
        secp256k1::Secp256k1::new()
            .verify_ecdsa(&self.digest(), signature, pubkey)
            .is_ok()
    }
}

/// A signer that can sign any type that implements `Signable{curve}` trait.
#[derive(Clone, Debug)]
pub struct ECDSASigner {
    secp256k1_key: SecretKey,
}

impl ECDSASigner {
    /// Create a new signer with the given SECP256K1 secret key.
    pub fn new(secp256k1_key: SecretKey) -> Self {
        Self { secp256k1_key }
    }

    /// Sign the given object with the SECP256K1 key and ECDSA algorithm.
    pub fn sign_ecdsa<T: SignableECDSA>(&self, obj: &T) -> Signature {
        obj.sign(&self.secp256k1_key)
    }

    /// Verify the given object with the SECP256K1 key and ECDSA algorithm.
    #[allow(dead_code)]
    pub fn verify_ecdsa<T: SignableECDSA>(
        &self,
        obj: &T,
        sig: &Signature,
        pubkey: &PublicKey,
    ) -> bool {
        obj.verify(sig, pubkey)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_util::TestSignableData;

    use super::ECDSASigner;
    use secp256k1::{PublicKey, SecretKey};

    #[test]
    fn test_ecdsa_signer() {
        let secp256k1_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let signer = ECDSASigner::new(secp256k1_key);

        let message = TestSignableData {
            data: vec![1, 2, 3, 4],
        };

        let signature = signer.sign_ecdsa(&message);
        let pubkey = PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secp256k1_key);

        assert!(signer.verify_ecdsa(&message, &signature, &pubkey));
    }
}
