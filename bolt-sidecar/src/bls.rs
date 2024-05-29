use blst::{
    min_pk::{PublicKey, SecretKey, Signature},
    BLST_ERROR,
};

/// Domain Separation Tag used in Ethereum 2.0 BLS signatures.
const ETH2_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Trait for types that can be signed with a BLS private key.
pub(crate) trait Signable {
    /// Create a digest of the object to be signed. This is dependent on
    /// the specific type of object being signed and the format required.
    fn as_signable(&self) -> Vec<u8>;

    /// Sign the object with the provided private key and return the
    /// signature as a hex-encoded string.
    fn sign_bls(&self, sk: &SecretKey) -> Signature {
        sk.sign(self.as_signable().as_ref(), ETH2_BLS_DST, &[])
    }

    /// Verify a BLS signature for the object using the provided public key.
    /// Returns true if the signature is valid, false otherwise.
    fn verify_bls_single(&self, pk: &PublicKey, sig: &Signature) -> eyre::Result<bool> {
        Ok(sig.verify(
            true,
            self.as_signable().as_ref(),
            ETH2_BLS_DST,
            &[],
            pk,
            true,
        ) == BLST_ERROR::BLST_SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::Signable;

    struct TestSignableData {
        data: Vec<u8>,
    }

    impl Signable for TestSignableData {
        fn as_signable(&self) -> Vec<u8> {
            self.data.clone()
        }
    }

    #[test]
    fn test_signable() -> eyre::Result<()> {
        let sk = SecretKey::key_gen(&[], &[]).unwrap();
        let pk = sk.sk_to_pk();

        let msg = TestSignableData {
            data: "hello, world!".as_bytes().to_vec(),
        };

        let sig = msg.sign_bls(&sk);
        assert!(msg.verify_bls_single(&pk, &sig).unwrap());

        Ok(())
    }
}
