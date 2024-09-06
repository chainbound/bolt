use alloy::{
    primitives::keccak256,
    signers::k256::sha2::{Digest, Sha256},
};
use secp256k1::Message;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{bls::BLSSig, ecdsa::SignableECDSA, SignableBLS},
    primitives::{deserialize_txs, serialize_txs},
};

use super::{FullTransaction, InclusionRequest};

/// What the proposer sidecar will need to sign to confirm the inclusion request.
impl SignableECDSA for ConstraintsMessage {
    fn digest(&self) -> Message {
        let mut data = Vec::new();
        data.extend_from_slice(&self.validator_index.to_le_bytes());
        data.extend_from_slice(&self.slot.to_le_bytes());

        let mut constraint_bytes = Vec::new();
        for constraint in &self.constraints {
            constraint_bytes.extend_from_slice(&constraint.envelope_encoded().0);
        }
        data.extend_from_slice(&constraint_bytes);

        let hash = keccak256(data).0;
        Message::from_digest_slice(&hash).expect("digest")
    }
}

/// The inclusion request transformed into an explicit list of signed constraints
/// that need to be forwarded to the PBS pipeline to inform block production.
pub type BatchedSignedConstraints = Vec<SignedConstraints>;

/// A container for a list of constraints and the signature of the proposer sidecar.
///
/// Reference: https://chainbound.github.io/bolt-docs/api/builder#constraints
#[derive(Serialize, Default, Debug, Clone, PartialEq)]
pub struct SignedConstraints {
    /// The constraints that need to be signed.
    pub message: ConstraintsMessage,
    /// The signature of the proposer sidecar.
    pub signature: BLSSig,
}

/// A message that contains the constraints that need to be signed by the proposer sidecar.
///
/// Reference: https://chainbound.github.io/bolt-docs/api/builder#constraints
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ConstraintsMessage {
    /// The validator index of the proposer sidecar.
    pub validator_index: u64,
    /// The consensus slot at which the constraints are valid
    pub slot: u64,
    /// Indicates whether these constraints are only valid on the top of the block.
    /// NOTE: Per slot, only 1 top-of-block bundle is valid.
    pub top: bool,
    /// The constraints that need to be signed.
    #[serde(deserialize_with = "deserialize_txs", serialize_with = "serialize_txs")]
    pub constraints: Vec<FullTransaction>,
}

impl ConstraintsMessage {
    /// Builds a constraints message from an inclusion request and metadata
    pub fn build(validator_index: u64, request: InclusionRequest) -> Self {
        let constraints = request.txs;

        Self { validator_index, slot: request.slot, top: false, constraints }
    }
}

impl SignableBLS for ConstraintsMessage {
    fn tree_hash_root(&self) -> [u8; 32] {
        let mut hasher = MerkleHasher::with_leaves(self.total_leaves());

        hasher
            .write(&self.validator_index.to_le_bytes())
            .expect("Should write validator index bytes");
        hasher.write(&self.slot.to_le_bytes()).expect("Should write slot bytes");
        hasher.write(&(self.top as u8).to_le_bytes()).expect("Should write top flag");

        for constraint in &self.constraints {
            hasher.update(constraint.hash());
        }

        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut rng = rand::thread_rng();

        // Generate random values for the `ConstraintsMessage` fields
        let validator_index = random_u64(&mut rng);
        let slot = random_u64(&mut rng);
        let top = false;
        let constraints = random_constraints(1); // Generate 'n' random constraints

        // Create a random `ConstraintsMessage`
        let mut message = ConstraintsMessage { validator_index, slot, top, constraints };
        message.validator_index = 0;
        message.slot = 0;
        message.top = false;

        // Compute tree hash root
        let digest = SignableBLS::digest(&message);

        // Verify that the tree hash root is a valid 32-byte array
        assert_eq!(digest.len(), 32, "Digest should be 32 bytes long");
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut rng = rand::thread_rng();

        // Generate random values for the `ConstraintsMessage` fields
        let validator_index = random_u64(&mut rng);
        let slot = random_u64(&mut rng);
        let top = false;
        let constraints = random_constraints(2); // Generate 'n' random constraints

        // Create a random `ConstraintsMessage`
        let message = ConstraintsMessage { validator_index, slot, top, constraints };

        // Serialize the `ConstraintsMessage` to JSON
        let json = serde_json::to_string(&message).unwrap();

        // Deserialize the JSON back to a `ConstraintsMessage`
        let deserialized_message: ConstraintsMessage = serde_json::from_str(&json).unwrap();

        // Verify that the deserialized message is equal to the original message
        assert_eq!(message, deserialized_message);
    }
}
