use alloy::primitives::{TxHash, B256};

use super::types::{ConstraintsWithProofData, InclusionProofs};

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("Leaves and indices length mismatch")]
    LengthMismatch,
    #[error("Mismatch in provided leaves and leaves to prove")]
    LeavesMismatch,
    #[error("Hash not found in constraints cache: {0:?}")]
    MissingHash(TxHash),
    #[error("Proof verification failed")]
    VerificationFailed,
}

/// Returns the length of the leaves that need to be proven (i.e. all transactions).
fn total_leaves(constraints: &[ConstraintsWithProofData]) -> usize {
    constraints.iter().map(|c| c.proof_data.len()).sum()
}

/// Verifies the provided multiproofs against the constraints & transactions root.
/// TODO: support bundle proof verification a.k.a. relative ordering!
pub fn verify_multiproofs(
    constraints: &[ConstraintsWithProofData],
    proofs: &InclusionProofs,
    root: B256,
) -> Result<(), ProofError> {
    // Check if the length of the leaves and indices match
    if proofs.transaction_hashes.len() != proofs.generalized_indeces.len() {
        return Err(ProofError::LengthMismatch);
    }

    let total_leaves = total_leaves(constraints);

    // Check if the total leaves matches the proofs provided
    if total_leaves != proofs.total_leaves() {
        return Err(ProofError::LeavesMismatch);
    }

    // Get all the leaves from the saved constraints
    let mut leaves = Vec::with_capacity(proofs.total_leaves());

    for hash in &proofs.transaction_hashes {
        let mut found = false;
        for constraint in constraints {
            for (saved_hash, leaf) in &constraint.proof_data {
                if saved_hash == hash {
                    found = true;
                    leaves.push(B256::from(leaf.0));
                    break;
                }
            }
            if found {
                break;
            }
        }

        // If the hash is not found in the constraints cache, return an error
        if !found {
            return Err(ProofError::MissingHash(*hash));
        }
    }

    // Verify the Merkle multiproof against the root
    ssz_rs::multiproofs::verify_merkle_multiproof(
        &leaves,
        &proofs.merkle_hashes,
        &proofs.generalized_indeces,
        root,
    )
    .map_err(|_| ProofError::VerificationFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use ssz_rs::{Node, Path, PathElement, Prove};

    use super::*;

    use crate::{testutil::*, types::ConstraintsMessage};

    #[test]
    fn test_single_multiproof() {
        let test_block = read_test_block();
        println!("State root: {:?}", test_block.message.state_root);

        let (root, transactions) = read_test_transactions();

        let index = rand::random::<usize>() % transactions.len();

        println!("Index to prove: {index}");

        let c1 = ConstraintsMessage {
            validator_index: 0,
            slot: 1,
            top: false,
            transactions: vec![transactions[index].clone()],
        };

        let c1_with_data = ConstraintsWithProofData::try_from(c1).unwrap();

        println!("Constraints: {c1_with_data:?}");

        let root_node = root as Node;

        // Generate the path from the transaction indexes
        let path = path_from_indeces(&[index]);
        let (multi_proof, witness) = root_node.multi_prove(&[&[0.into()]]).unwrap();

        // Root and witness must be the same
        assert_eq!(root, witness);

        println!("Witness: {witness:?}");

        // assert!(verify_multiproofs(&[c1_with_data], proofs, root).is_ok());
    }

    fn path_from_indeces(indeces: &[usize]) -> Vec<PathElement> {
        indeces
            .iter()
            .map(|i| PathElement::from(tx_index_to_generalized_index(*i)))
            .collect::<Vec<_>>()
    }

    /// Converts a transaction index to a generalized index.
    fn tx_index_to_generalized_index(index: usize) -> usize {
        2usize * 2usize.pow(21u32) + index
    }
}
