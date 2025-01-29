use alloy::{
    consensus::Transaction,
    primitives::{Address, TxHash, U256},
};
use ethereum_consensus::{
    crypto::{KzgCommitment, KzgProof},
    deneb::mainnet::{Blob, BlobsBundle},
};
use reth_primitives::TransactionSigned;
use tracing::warn;

use crate::{
    common::transactions::max_transaction_cost,
    primitives::{
        diffs::{AccountDiff, BalanceDiff, StateDiff},
        AccountState, FullTransaction, SignedConstraints, TransactionExt,
    },
};

/// A block template that serves as a fallback block, but is also used
/// to keep intermediary state for new commitment requests.
///
/// # Roles
/// - Fallback block template.
/// - Intermediary state for new commitment requests.
/// - Simulate new commitment requests.
/// - Update state every block, to invalidate old commitments.
/// - Make sure we DO NOT accept invalid commitments in any circumstances.
#[derive(Debug, Default)]
pub struct BlockTemplate {
    /// The state diffs per address given the list of commitments.
    pub(crate) state_diff: StateDiff,
    /// The signed constraints associated to the block
    pub signed_constraints_list: Vec<SignedConstraints>,
}

impl BlockTemplate {
    /// Return the state diff of the block template.
    pub fn get_diff(&self, address: &Address) -> Option<AccountDiff> {
        self.state_diff.get_diff(address)
    }

    /// Returns the cloned list of transactions from the constraints.
    #[inline]
    pub fn transactions(&self) -> Vec<FullTransaction> {
        self.signed_constraints_list.iter().flat_map(|sc| sc.message.transactions.clone()).collect()
    }

    /// Converts the list of signed constraints into a list of signed transactions. Use this when
    /// building a local execution payload.
    #[inline]
    pub fn as_signed_transactions(&self) -> Vec<TransactionSigned> {
        self.signed_constraints_list
            .iter()
            .flat_map(|sc| sc.message.transactions.iter().map(|c| c.clone().into_signed()))
            .collect()
    }

    /// Get all the transaction hashes in the signed constraints list.
    #[inline]
    pub fn transaction_hashes(&self) -> Vec<TxHash> {
        self.signed_constraints_list
            .iter()
            .flat_map(|sc| sc.message.transactions.iter().map(|c| *c.hash()))
            .collect()
    }

    /// Converts the list of signed constraints into a list of all blobs in all transactions
    /// in the constraints. Use this when building a local execution payload.
    #[inline]
    pub fn as_blobs_bundle(&self) -> BlobsBundle {
        let (commitments, proofs, blobs) =
            self.signed_constraints_list
                .iter()
                .flat_map(|sc| sc.message.transactions.iter())
                .filter_map(|c| c.blob_sidecar())
                .fold(
                    (Vec::new(), Vec::new(), Vec::new()),
                    |(mut commitments, mut proofs, mut blobs), bs| {
                        commitments.extend(bs.commitments.iter().map(|c| {
                            KzgCommitment::try_from(c.as_slice()).expect("both are 48 bytes")
                        }));
                        proofs.extend(
                            bs.proofs.iter().map(|p| {
                                KzgProof::try_from(p.as_slice()).expect("both are 48 bytes")
                            }),
                        );
                        blobs.extend(bs.blobs.iter().map(|b| {
                            Blob::try_from(b.as_slice()).expect("both are 131_072 bytes")
                        }));
                        (commitments, proofs, blobs)
                    },
                );

        BlobsBundle { commitments, proofs, blobs }
    }

    /// Returns the length of the transactions in the block template.
    #[inline]
    pub fn transactions_len(&self) -> usize {
        self.signed_constraints_list.iter().fold(0, |acc, sc| acc + sc.message.transactions.len())
    }

    /// Returns the committed gas in the block template.
    #[inline]
    pub fn committed_gas(&self) -> u64 {
        self.signed_constraints_list.iter().fold(0, |acc, sc| {
            acc + sc.message.transactions.iter().fold(0, |acc, c| acc + c.gas_limit())
        })
    }

    /// Returns the blob count of the block template.
    #[inline]
    pub fn blob_count(&self) -> usize {
        self.signed_constraints_list.iter().fold(0, |mut acc, sc| {
            acc += sc.message.transactions.iter().fold(0, |acc, c| {
                acc + c.as_eip4844().map(|tx| tx.blob_versioned_hashes.len()).unwrap_or(0)
            });

            acc
        })
    }

    /// Adds a list of constraints to the block template and updates the state diff.
    pub fn add_constraints(&mut self, constraints: SignedConstraints) {
        for constraint in &constraints.message.transactions {
            let max_cost = max_transaction_cost(constraint);

            // Increase the nonce and decrease the balance of the sender
            self.state_diff
                .diffs
                .entry(*constraint.sender().expect("recovered sender"))
                .and_modify(|diff| {
                    *diff = AccountDiff::new(
                        diff.nonce().saturating_add(1),
                        BalanceDiff::new(
                            diff.balance().increase(),
                            diff.balance().decrease().saturating_add(max_cost),
                        ),
                    )
                })
                .or_insert(AccountDiff::new(1, BalanceDiff::new(U256::ZERO, max_cost)));

            // If there is an ETH transfer and it's not a contract creation, increase the balance
            // of the recipient so that it can send inclusion requests on this preconfirmed state.
            let value = constraint.tx.value();
            if value.is_zero() {
                continue;
            }
            let Some(recipient) = constraint.to() else { continue };

            self.state_diff
                .diffs
                .entry(recipient)
                .and_modify(|diff| {
                    *diff = AccountDiff::new(
                        diff.nonce().saturating_add(1),
                        BalanceDiff::new(
                            diff.balance().increase().saturating_add(constraint.tx.value()),
                            diff.balance().decrease(),
                        ),
                    )
                })
                .or_insert(AccountDiff::new(
                    0,
                    BalanceDiff::new(constraint.tx.value(), U256::ZERO),
                ));
        }

        self.signed_constraints_list.push(constraints);
    }

    /// Remove all signed constraints at the specified index and updates the state diff
    fn remove_constraints_at_index(&mut self, index: usize) {
        let constraints = self.signed_constraints_list.remove(index);

        for constraint in &constraints.message.transactions {
            let max_cost = max_transaction_cost(constraint);

            self.state_diff
                .diffs
                .entry(*constraint.sender().expect("recovered sender"))
                .and_modify(|diff| {
                    *diff = AccountDiff::new(
                        diff.nonce().saturating_sub(1),
                        BalanceDiff::new(
                            diff.balance().increase(),
                            diff.balance().decrease().saturating_sub(max_cost),
                        ),
                    )
                });

            // If there is an ETH transfer and it's not a contract creation, remove the balance
            // increase of the recipient.
            let value = constraint.tx.value();
            if value.is_zero() {
                continue;
            }
            let Some(recipient) = constraint.to() else { continue };

            self.state_diff.diffs.entry(recipient).and_modify(|diff| {
                *diff = AccountDiff::new(
                    diff.nonce().saturating_sub(1),
                    BalanceDiff::new(
                        diff.balance().increase().saturating_sub(constraint.tx.value()),
                        diff.balance().decrease(),
                    ),
                )
            });
        }
    }

    /// Retain removes any transactions that conflict with the given account state.
    pub fn retain(&mut self, address: Address, state: AccountState) {
        let mut indexes: Vec<usize> = Vec::new();

        // The preconfirmations made by such address, and the indexes of the signed constraints
        // in which they appear
        let constraints_with_address: Vec<(usize, Vec<&FullTransaction>)> = self
            .signed_constraints_list
            .iter()
            .enumerate()
            .map(|(idx, c)| (idx, &c.message.transactions))
            .filter(|(_idx, c)| c.iter().any(|c| c.sender().expect("recovered sender") == &address))
            .map(|(idx, c)| {
                (
                    idx,
                    c.iter()
                        .filter(|c| c.sender().expect("recovered sender") == &address)
                        .collect(),
                )
            })
            .collect();

        // For every preconfirmation, gather the max total balance cost,
        // and find the one with the lowest nonce
        let (max_total_cost, min_nonce) = constraints_with_address
            .iter()
            .flat_map(|c| c.1.clone())
            .fold((U256::ZERO, u64::MAX), |(total_cost, min_nonce), c| {
                (total_cost + max_transaction_cost(c), min_nonce.min(c.nonce()))
            });

        if state.balance < max_total_cost || state.transaction_count > min_nonce {
            // Remove invalidated constraints due to balance / nonce of chain state
            warn!(
                %address,
                "Removing invalidated constraints for address"
            );
            indexes = constraints_with_address.iter().map(|(i, _)| *i).collect();
        }

        for index in indexes.into_iter().rev() {
            self.remove_constraints_at_index(index);
        }
    }
}
