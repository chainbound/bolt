use alloy::primitives::{keccak256, Address};
use cb_common::pbs::{DenebSpec, EthSpec, Transaction};
use secp256k1::Message;
use serde::Serialize;
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
            constraint_bytes.extend_from_slice(&constraint.as_bytes());
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
/// Reference: https://chainbound.github.io/bolt-docs/api/builder-api#ethv1builderconstraints
#[derive(Serialize, Default, Debug, Clone, PartialEq)]
pub struct SignedConstraints {
    /// The constraints that need to be signed.
    pub message: ConstraintsMessage,
    /// The signature of the proposer sidecar.
    pub signature: BLSSig,
}

/// A message that contains the constraints that need to be signed by the proposer sidecar.
///
/// Reference: https://chainbound.github.io/bolt-docs/api/builder-api#ethv1builderconstraints
#[derive(Serialize, Debug, Clone, PartialEq, Default)]
pub struct ConstraintsMessage {
    /// The validator index of the proposer sidecar.
    pub validator_index: u64,
    /// The consensus slot at which the constraints are valid
    pub slot: u64,
    /// Indicates whether these constraints are only valid on the top of the block.
    /// NOTE: Per slot, only 1 top-of-block bundle is valid.
    pub top: bool,
    /// The constraints that need to be signed.
    pub constraints: Vec<Constraint>,
}

impl ConstraintsMessage {
    /// Builds a constraints message from an inclusion request and metadata
    pub fn build(validator_index: u64, request: InclusionRequest) -> Self {
        let constraints =
            request.txs.into_iter().map(|tx| Constraint::from_transaction(tx, None)).collect();

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
                        constraint.transaction.envelope_encoded().to_vec(),
                    )
                    .tree_hash_root()
                    .as_bytes(),
                )
                .expect("Should write transaction root");
        }

        hasher.finish().unwrap().0
    }
}

/// A general constraint on block building.
///
/// Reference: https://chainbound.github.io/bolt-docs/api/builder-api#ethv1builderconstraints
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Constraint {
    /// The optional index at which the transaction needs to be included in the block
    pub index: Option<u64>,
    /// The transaction to be included in the block, in hex format
    #[serde(rename(serialize = "tx"))]
    pub(crate) transaction: FullTransaction,
}

impl Constraint {
    /// Builds a constraint from a transaction, with an optional index
    pub fn from_transaction(transaction: FullTransaction, index: Option<u64>) -> Self {
        Self { transaction, index }
    }

    /// Converts the constraint to a byte representation useful for signing
    /// TODO: remove if we go with SSZ
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.transaction.encode_enveloped(&mut data);
        data.extend_from_slice(&self.index.unwrap_or(0).to_le_bytes());
        data
    }

    pub fn sender(&self) -> Address {
        self.transaction.sender().expect("Recovered sender")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::ThreadRng, Rng};

    fn random_u64(rng: &mut ThreadRng) -> u64 {
        rng.gen_range(0..u64::MAX)
    }

    fn random_constraints(rng: &mut ThreadRng, count: usize) -> Vec<Constraint> {
        // Random inclusion request
        let json_req = r#"{
            "slot": 10,
            "txs": ["0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4"]
        }"#;

        let req: InclusionRequest = serde_json::from_str(json_req).unwrap();

        (0..count)
            .map(|_| {
                Constraint::from_transaction(
                    req.txs.first().unwrap().clone(),
                    Some(random_u64(rng)),
                )
            })
            .collect()
    }

    #[test]
    fn test_tree_hash_root() {
        let mut rng = rand::thread_rng();

        // Generate random values for the `ConstraintsMessage` fields
        let validator_index = random_u64(&mut rng);
        let slot = random_u64(&mut rng);
        let top = false;
        let constraints = random_constraints(&mut rng, 10); // Generate 10 random constraints

        // Create a random `ConstraintsMessage`
        let message = ConstraintsMessage { validator_index, slot, top, constraints };

        // Compute tree hash root
        let tree_root = message.tree_hash_root();

        // Verify that the tree hash root is a valid 32-byte array
        assert_eq!(tree_root.len(), 32, "Tree hash root should be 32 bytes long");

        // Additional checks can be added here, depending on your specific requirements
        println!("Computed tree hash root: {:?}", tree_root);
    }
}
