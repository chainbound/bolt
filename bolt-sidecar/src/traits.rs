use secp256k1::{
    hashes::{sha256, Hash},
    Message, Secp256k1, SecretKey,
};

/// Trait for types that can be signed with an ECDSA private key.
pub(crate) trait Signable {
    /// Create a digest of the object to be signed. This is dependent on
    /// the specific type of object being signed and the format required.
    fn as_signable(&self) -> Vec<u8>;

    /// Sign the object with the provided private key and return the
    /// signature as a hex-encoded string.
    ///
    /// The default implementation uses the secp256k1 library.
    fn sign_ecdsa(&self, pk: SecretKey) -> String {
        let digest = sha256::Hash::hash(&self.as_signable());
        let message = Message::from_digest(digest.to_byte_array());

        Secp256k1::new().sign_ecdsa(&message, &pk).to_string()
    }
}
