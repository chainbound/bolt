use alloy::signers::k256::sha2::{Digest, Sha256};
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use serde::{Deserialize, Serialize};

use crate::crypto::{bls::BLSSig, SignableBLS};

use super::{deserialize_txs, serialize_txs, FullTransaction, InclusionRequest};

/// The inclusion request transformed into an explicit list of signed constraints
/// that need to be forwarded to the PBS pipeline to inform block production.
pub type BatchedSignedConstraints = Vec<SignedConstraints>;

/// A container for a list of constraints and the signature of the proposer sidecar.
///
/// Reference: https://chainbound.github.io/bolt-docs/api/builder#constraints
#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct SignedConstraints {
    /// The constraints that need to be signed.
    pub message: ConstraintsMessage,
    /// The signature of the proposer sidecar.
    pub signature: BLSSig,
}

/// A message that contains the constraints that need to be signed by the proposer sidecar.
///
/// Reference: https://chainbound.github.io/bolt-docs/api/builder#constraints
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default, Eq)]
pub struct ConstraintsMessage {
    /// The validator pubkey of the proposer sidecar.
    pub pubkey: BlsPublicKey,
    /// The consensus slot at which the constraints are valid
    pub slot: u64,
    /// Indicates whether these constraints are only valid on the top of the block.
    /// NOTE: Per slot, only 1 top-of-block bundle is valid.
    pub top: bool,
    /// The constraints that need to be signed.
    #[serde(deserialize_with = "deserialize_txs", serialize_with = "serialize_txs")]
    pub transactions: Vec<FullTransaction>,
}

impl ConstraintsMessage {
    /// Builds a constraints message from an inclusion request and metadata
    pub fn build(pubkey: BlsPublicKey, request: InclusionRequest) -> Self {
        let transactions = request.txs;

        Self { pubkey, slot: request.slot, top: false, transactions }
    }

    /// Builds a constraints message from a single transaction.
    pub fn from_transaction(pubkey: BlsPublicKey, slot: u64, transaction: FullTransaction) -> Self {
        Self { pubkey, slot, top: false, transactions: vec![transaction] }
    }
}

impl SignableBLS for ConstraintsMessage {
    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.pubkey.to_vec());
        hasher.update(self.slot.to_le_bytes());
        hasher.update((self.top as u8).to_le_bytes());

        for tx in &self.transactions {
            hasher.update(tx.hash());
        }

        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use crate::signer::local::LocalSigner;

    use super::*;
    use alloy::primitives::bytes;
    use blst::min_pk::Signature as BlsSignature;
    use rand::{rngs::ThreadRng, Rng};

    fn random_u64(rng: &mut ThreadRng) -> u64 {
        rng.gen_range(0..u64::MAX)
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

    #[test]
    fn test_bls_digest() {
        // Generate random values for the `ConstraintsMessage` fields
        let pubkey = BlsPublicKey::default();
        let slot = 0;
        let top = false;
        let transactions = random_constraints(1); // Generate 'n' random constraints

        // Create a random `ConstraintsMessage`
        let message = ConstraintsMessage { pubkey, slot, top, transactions };

        // Compute tree hash root
        let digest = SignableBLS::digest(&message);

        // Verify that the tree hash root is a valid 32-byte array
        assert_eq!(digest.len(), 32, "Digest should be 32 bytes long");
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut rng = rand::thread_rng();

        // Generate random values for the `ConstraintsMessage` fields
        let pubkey = BlsPublicKey::default();
        let slot = random_u64(&mut rng);
        let top = false;
        let transactions = random_constraints(2); // Generate 'n' random constraints

        // Create a random `ConstraintsMessage`
        let message = ConstraintsMessage { pubkey, slot, top, transactions };

        // Serialize the `ConstraintsMessage` to JSON
        let json = serde_json::to_string(&message).unwrap();

        // Deserialize the JSON back to a `ConstraintsMessage`
        let deserialized_message: ConstraintsMessage = serde_json::from_str(&json).unwrap();

        // Verify that the deserialized message is equal to the original message
        assert_eq!(message, deserialized_message);
    }

    #[test]
    fn test_constraints_signature_roundtrip() {
        let signer = LocalSigner::random();

        let tx_bytes = bytes!("f8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead38808360306ca06664c078fa60bd3ece050903dd295949908dd9686ec8871fa558f868e031cd39a00ed4f0b122b32b73f19230fabe6a726e2d07f84eda5beaa42a1ae1271bdee39f").to_vec();
        let tx = FullTransaction::decode_enveloped(tx_bytes.as_slice()).unwrap();

        let constraint = ConstraintsMessage::from_transaction(signer.pubkey(), 165, tx);

        let digest = constraint.digest();
        let signature = signer.sign_commit_boost_root(digest).unwrap();
        let signed_constraints = SignedConstraints { message: constraint, signature };

        // verify the signature
        let blst_sig = BlsSignature::from_bytes(signed_constraints.signature.as_ref()).unwrap();
        assert!(signer.verify_commit_boost_root(digest, &blst_sig).is_ok());
    }
}
