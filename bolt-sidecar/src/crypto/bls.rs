use std::fmt::Debug;

use alloy::primitives::FixedBytes;
use blst::{min_pk::Signature, BLST_ERROR};
use rand::RngCore;

pub use blst::min_pk::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
pub use ethereum_consensus::deneb::BlsSignature;

/// The BLS Domain Separator used in Ethereum 2.0.
pub const BLS_DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A fixed-size byte array for BLS signatures.
pub type BLSSig = FixedBytes<96>;

/// Trait for any types that can be signed and verified with BLS.
/// This trait is used to abstract over the signing and verification of different types.
pub trait SignableBLS {
    /// Returns the digest of the object.
    fn digest(&self) -> [u8; 32];

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
        signature.verify(false, &self.digest(), BLS_DST_PREFIX, &[], pubkey, true) ==
            BLST_ERROR::BLST_SUCCESS
    }
}

/// A generic signing trait to generate BLS signatures.
#[async_trait::async_trait]
pub trait SignerBLS: Send + Debug {
    /// Sign the given data and return the signature.
    async fn sign(&self, data: &[u8; 32]) -> eyre::Result<BLSSig>;
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
        Self { key: random_bls_secret() }
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

#[async_trait::async_trait]
impl SignerBLS for Signer {
    async fn sign(&self, data: &[u8; 32]) -> eyre::Result<BLSSig> {
        let sig = sign_with_prefix(&self.key, data);
        Ok(BLSSig::from(sig.to_bytes()))
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
        crypto::bls::{SignableBLS, Signer, SignerBLS}, primitives::{ConstraintsMessage, DelegationMessage, FullTransaction, InclusionRequest, RevocationMessage, SignedConstraints, SignedDelegation, SignedRevocation}, test_util::{test_bls_secret_key, TestSignableData}
    };

    use blst::min_pk::SecretKey;
    use ethereum_consensus::crypto::{PublicKey, Signature};
    use rand::Rng;

    #[tokio::test]
    async fn test_bls_signer() {
        let key = test_bls_secret_key();
        let pubkey = key.sk_to_pk();
        let signer = Signer::new(key);

        // Generate random data for the test
        let mut rng = rand::thread_rng();
        let mut data = [0u8; 32];
        rng.fill(&mut data);
        let msg = TestSignableData { data };

        let signature = SignerBLS::sign(&signer, &msg.digest()).await.unwrap();
        let sig = blst::min_pk::Signature::from_bytes(signature.as_ref()).unwrap();
        assert!(signer.verify(&msg, &sig, &pubkey));
    }

    fn random_constraints(count: usize) -> Vec<FullTransaction> {
        // Random inclusion request
        let json_req = r#"{
            "slot": 10,
            "txs": ["0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4"]
        }"#;

        let req: InclusionRequest = serde_json::from_str(json_req).unwrap();

        (0..count).map(|_| req.txs.first().unwrap().clone()).collect()
    }

    #[tokio::test]
    async fn generate_test_data() {
        let sk = test_bls_secret_key();
        let pk = sk.sk_to_pk();
        let signer = Signer::new(sk);

        println!("Validator Public Key: {}", hex::encode(pk.to_bytes()));

        // Generate a delegatee's BLS secret key and public key
        let delegatee_ikm: [u8; 32] = rand::thread_rng().gen();
        let delegatee_sk = SecretKey::key_gen(&delegatee_ikm, &[]).expect("Failed to generate delegatee secret key");
        let delegatee_pk = delegatee_sk.sk_to_pk();

        // Prepare a Delegation message
        let delegation_msg = DelegationMessage {
            validator_pubkey: PublicKey::try_from(pk.to_bytes().as_slice()).expect("Failed to convert validator public key"),
            delegatee_pubkey: PublicKey::try_from(delegatee_pk.to_bytes().as_slice()).expect("Failed to convert delegatee public key"),
        };

        let digest = SignableBLS::digest(&delegation_msg);

        // Sign the Delegation message
        let delegation_signature = SignerBLS::sign(&signer, &digest).await.unwrap();

        // Create SignedDelegation
        let signed_delegation = SignedDelegation {
            message: delegation_msg,
            signature: Signature::try_from(delegation_signature.as_ref()).expect("Failed to convert delegation signature"),
        };

        // Output SignedDelegation
        println!("{}", serde_json::to_string_pretty(&signed_delegation).unwrap());

        // Prepare a revocation message
        let revocation_msg = RevocationMessage {
            validator_pubkey: PublicKey::try_from(pk.to_bytes().as_slice()).expect("Failed to convert validator public key"),
            delegatee_pubkey: PublicKey::try_from(delegatee_pk.to_bytes().as_slice()).expect("Failed to convert delegatee public key"),
        };

        let digest = SignableBLS::digest(&revocation_msg);

        // Sign the Revocation message
        let revocation_signature = SignerBLS::sign(&signer, &digest).await.unwrap();

        // Create SignedRevocation
        let signed_revocation = SignedRevocation {
            message: revocation_msg,
            signature: Signature::try_from(revocation_signature.as_ref()).expect("Failed to convert revocation signature"),
        };

        // Output SignedRevocation
        println!("{}", serde_json::to_string_pretty(&signed_revocation).unwrap());

        let transactions = random_constraints(2);

        // Prepare a ConstraintsMessage
        let constraints_msg = ConstraintsMessage {
            pubkey: PublicKey::try_from(pk.to_bytes().as_slice()).expect("Failed to convert validator public key"),
            slot: 2,
            top: false,
            transactions,
        };

        let digest = SignableBLS::digest(&constraints_msg);

        // Sign the ConstraintsMessage
        let constraints_signature = SignerBLS::sign(&signer, &digest).await.unwrap();

        // Create SignedConstraints
        let signed_constraints = SignedConstraints {
            message: constraints_msg,
            signature: constraints_signature,
        };

        // Output SignedConstraints
        println!("{}", serde_json::to_string_pretty(&signed_constraints).unwrap());
    }
}
