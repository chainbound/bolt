use alloy::primitives::keccak256;
use cb_common::pbs::{DenebSpec, EthSpec, Transaction};
use secp256k1::Message;
use serde::{Deserialize, Serialize};
use tree_hash::{MerkleHasher, TreeHash};

use crate::crypto::{bls::BLSSig, ecdsa::SignableECDSA, SignableBLS};

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
    pub constraints: Vec<FullTransaction>,
}

impl ConstraintsMessage {
    /// Builds a constraints message from an inclusion request and metadata
    pub fn build(validator_index: u64, request: InclusionRequest) -> Self {
        let constraints = request.txs;

        Self { validator_index, slot: request.slot, top: false, constraints }
    }

    /// Returns the total number of leaves in the tree.
    fn total_leaves(&self) -> usize {
        4 + self.constraints.len()
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
            hasher
                .write(
                    Transaction::<<DenebSpec as EthSpec>::MaxBytesPerTransaction>::from(
                        constraint.envelope_encoded().to_vec(),
                    )
                    .tree_hash_root()
                    .as_bytes(),
                )
                .expect("Should write transaction root");
        }

        hasher.finish().unwrap().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex::ToHexExt;
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
    fn test_tree_hash_root() {
        let mut rng = rand::thread_rng();

        // Generate random values for the `ConstraintsMessage` fields
        let validator_index = random_u64(&mut rng);
        let slot = random_u64(&mut rng);
        let top = false;
        let constraints = random_constraints(1); // Generate 'n' random constraints

        // Create a random `ConstraintsMessage`
        let message = ConstraintsMessage { validator_index, slot, top, constraints };

        // Compute tree hash root
        let tree_root = message.tree_hash_root();

        // Verify that the tree hash root is a valid 32-byte array
        assert_eq!(tree_root.len(), 32, "Tree hash root should be 32 bytes long");

        // Additional checks can be added here, depending on your specific requirements
        println!("Computed tree hash root: {:?}", tree_root.encode_hex());
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
