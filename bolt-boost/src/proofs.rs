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
    use alloy::{
        hex::FromHex,
        primitives::{Bytes, B256},
    };
    use ssz_rs::{HashTreeRoot, List, PathElement, Prove};

    use crate::testutil::*;

    /// NOTE: This test is disabled because multiproof support has not landed in ssz-rs main yet.
    // #[test]
    // fn test_single_multiproof() {
    //     let (root, transactions) = read_test_transactions();
    //     println!(
    //         "Transactions root: {:?}, num transactions: {}",
    //         root,
    //         transactions.len()
    //     );

    //     // Shoudl be 1073741824, 1048576
    //     let transactions_list =
    //         transactions_to_ssz_list::<1073741824, 1048576>(transactions.clone());

    //     // let index = rand::random::<usize>() % transactions.len();
    //     let index = 51;

    //     println!("Index to prove: {index}");

    //     let root_node = transactions_list.hash_tree_root().unwrap();

    //     assert_eq!(root_node, root);

    //     // Generate the path from the transaction indexes
    //     let path = path_from_indeces(&[index]);

    //     let start_proof = std::time::Instant::now();
    //     let (multi_proof, witness) = transactions_list.multi_prove(&[&path]).unwrap();
    //     println!("Generated multiproof in {:?}", start_proof.elapsed());

    //     // Root and witness must be the same
    //     assert_eq!(root, witness);

    //     let start_verify = std::time::Instant::now();
    //     assert!(multi_proof.verify(witness).is_ok());
    //     println!("Verified multiproof in {:?}", start_verify.elapsed());

    //     // assert!(verify_multiproofs(&[c1_with_data], proofs, root).is_ok());
    // }

    #[test]
    fn test_single_proof() {
        let (root, transactions) = read_test_transactions();
        println!(
            "Transactions root: {:?}, num transactions: {}",
            root,
            transactions.len()
        );

        // Shoudl be 1073741824, 1048576
        let transactions_list =
            transactions_to_ssz_list::<1073741824, 1048576>(transactions.clone());

        // let index = rand::random::<usize>() % transactions.len();
        let index = 26;

        println!("Index to prove: {index}");

        // let c1 = ConstraintsMessage {
        //     validator_index: 0,
        //     slot: 1,
        //     top: false,
        //     transactions: vec![transactions[index].clone()],
        // };

        // let c1_with_data = ConstraintsWithProofData::try_from(c1).unwrap();

        let root_node = transactions_list.hash_tree_root().unwrap();

        assert_eq!(root_node, root);

        // Generate the path from the transaction indexes
        let path = path_from_indeces(&[index]);

        let start_proof = std::time::Instant::now();
        let (proof, witness) = transactions_list.prove(&path).unwrap();
        println!("Generated proof in {:?}", start_proof.elapsed());

        // Root and witness must be the same
        assert_eq!(root, witness);

        let start_verify = std::time::Instant::now();
        assert!(proof.verify(witness).is_ok());
        println!("Verified proof in {:?}", start_verify.elapsed());

        // assert!(verify_multiproofs(&[c1_with_data], proofs, root).is_ok());
    }

    #[test]
    /// Testdata from https://github.com/ferranbt/fastssz/blob/455b54c08c81c3a270b6a7160f92ce68408491d4/tests/codetrie_test.go#L195
    fn test_fastssz_multiproof() {
        let root =
            B256::from_hex("f1824b0084956084591ff4c91c11bcc94a40be82da280e5171932b967dd146e9")
                .unwrap();

        let proof = vec![
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "f58f76419d9235451a8290a88ba380d852350a1843f8f26b8257a421633042b4",
        ]
        .into_iter()
        .map(|hex| B256::from_hex(hex).unwrap())
        .collect::<Vec<_>>();

        let leaves = vec![
            "0200000000000000000000000000000000000000000000000000000000000000",
            "6001000000000000000000000000000000000000000000000000000000000000",
        ]
        .into_iter()
        .map(|hex| B256::from_hex(hex).unwrap())
        .collect::<Vec<_>>();

        let indices = vec![10usize, 49usize];

        assert!(
            ssz_rs::multiproofs::verify_merkle_multiproof(&leaves, &proof, &indices, root).is_ok()
        );
    }

    fn path_from_indeces(indeces: &[usize]) -> Vec<PathElement> {
        indeces
            .iter()
            .map(|i| PathElement::from(*i))
            .collect::<Vec<_>>()
    }

    fn transactions_to_ssz_list<const B: usize, const N: usize>(
        txs: Vec<Bytes>,
    ) -> List<List<u8, B>, N> {
        // fn transactions_to_ssz_list(txs: Vec<Bytes>) -> List<List<u8, 1073741824>, 1048576> {
        let inner: Vec<List<u8, B>> = txs
            .into_iter()
            .map(|tx| List::try_from(tx.to_vec()).unwrap())
            .collect();

        List::try_from(inner).unwrap()
    }
}
