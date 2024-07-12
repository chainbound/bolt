//! Package `template` contains the functionality for building local block templates that can
//! be used as a fallback. It's also used to keep any intermediary state that is needed to simulate
//! new commitment requests.

// Should this be a trait?

use std::collections::HashMap;

use alloy_primitives::{Address, U256};
use reth_primitives::{PooledTransactionsElement, TransactionSigned};

use crate::{
    common::max_transaction_cost,
    primitives::{constraint::Constraint, AccountState, SignedConstraints},
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
    state_diff: StateDiff,
    /// The signed constraints associated to the block
    pub signed_constraints_list: Vec<SignedConstraints>,
}

impl BlockTemplate {
    /// Return the state diff of the block template.
    pub fn state_diff(&self) -> &StateDiff {
        &self.state_diff
    }

    /// Adds a transaction to the block template and updates the state diff.
    pub fn add_constraints(&mut self, signed_constraints: SignedConstraints) {
        let mut address_to_state_diffs: HashMap<Address, AccountState> = HashMap::new();
        signed_constraints.message.constraints.iter().for_each(|c| {
            address_to_state_diffs
                .entry(c.sender)
                .and_modify(|state| {
                    state.balance = state
                        .balance
                        .saturating_add(max_transaction_cost(&c.transaction));
                    state.transaction_count += 1;
                })
                .or_insert(AccountState {
                    balance: max_transaction_cost(&c.transaction),
                    transaction_count: 1,
                });
        });

        // Now update intermediate state
        address_to_state_diffs.iter().for_each(|(address, diff)| {
            self.state_diff
                .diffs
                .entry(*address)
                .and_modify(|(nonce, balance)| {
                    *nonce += diff.transaction_count;
                    *balance += diff.balance;
                })
                .or_insert((diff.transaction_count, diff.balance));
        });

        self.signed_constraints_list.push(signed_constraints);
    }

    /// Returns all a clone of all transactions from the signed constraints list
    #[inline]
    pub fn transactions(&self) -> Vec<PooledTransactionsElement> {
        self.signed_constraints_list
            .iter()
            .flat_map(|sc| sc.message.constraints.iter().map(|c| c.transaction.clone()))
            .collect()
    }

    /// Converts the list of signed constraints into a list of signed transactions. Use this when building
    /// a local execution payload.
    #[inline]
    pub fn as_signed_transactions(&self) -> Vec<TransactionSigned> {
        self.signed_constraints_list
            .iter()
            .flat_map(|sc| {
                sc.message
                    .constraints
                    .iter()
                    .map(|c| c.transaction.clone().into_transaction())
            })
            .collect()
    }

    /// Returns the length of the transactions in the block template.
    #[inline]
    pub fn transactions_len(&self) -> usize {
        self.signed_constraints_list
            .iter()
            .fold(0, |acc, sc| acc + sc.message.constraints.len())
    }

    /// Returns the blob count of the block template.
    #[inline]
    pub fn blob_count(&self) -> usize {
        self.signed_constraints_list.iter().fold(0, |mut acc, sc| {
            acc += sc.message.constraints.iter().fold(0, |acc, c| {
                acc + c
                    .transaction
                    .as_eip4844()
                    .map(|tx| tx.blob_versioned_hashes.len())
                    .unwrap_or(0)
            });

            acc
        })
    }

    /// Remove all signed constraints at the specified index and updates the state diff
    fn remove_constraints_at_index(&mut self, index: usize) {
        let sc = self.signed_constraints_list.remove(index);
        let mut address_to_txs: HashMap<Address, Vec<&PooledTransactionsElement>> = HashMap::new();
        sc.message.constraints.iter().for_each(|c| {
            address_to_txs
                .entry(c.sender)
                .and_modify(|txs| txs.push(&c.transaction))
                .or_insert(vec![&c.transaction]);
        });

        // Collect the diff for each address and every transaction
        let address_to_diff: HashMap<Address, AccountState> = address_to_txs
            .iter()
            .map(|(address, txs)| {
                let mut state = AccountState::default();
                for tx in txs {
                    state.balance = state.balance.saturating_add(max_transaction_cost(tx));
                    state.transaction_count = state.transaction_count.saturating_sub(1);
                }
                (*address, state)
            })
            .collect();

        // Update intermediate state
        for (address, diff) in address_to_diff.iter() {
            self.state_diff
                .diffs
                .entry(*address)
                .and_modify(|(nonce, balance)| {
                    *nonce = nonce.saturating_sub(diff.transaction_count);
                    *balance += diff.balance;
                });
        }
    }

    /// Retain removes any transactions that conflict with the given account state.
    pub fn retain(&mut self, address: Address, state: AccountState) {
        let mut indexes: Vec<usize> = Vec::new();

        // The pre-confirmations made by such address, and the indexes of the signed constraints
        // in which they appear
        let constraints_with_address: Vec<(usize, Vec<&Constraint>)> = self
            .signed_constraints_list
            .iter()
            .enumerate()
            .map(|(idx, c)| (idx, &c.message.constraints))
            .filter(|(_idx, c)| c.iter().any(|c| c.sender == address))
            .map(|(idx, c)| (idx, c.iter().filter(|c| c.sender == address).collect()))
            .collect();

        // For every pre-confirmation, gather the max total balance cost,
        // and find the one with the lowest nonce
        let (max_total_cost, min_nonce) = constraints_with_address
            .iter()
            .flat_map(|c| c.1.clone())
            .fold((U256::ZERO, u64::MAX), |mut acc, c| {
                let nonce = c.transaction.nonce();
                if nonce < acc.1 {
                    acc.1 = nonce;
                }
                acc.0 += max_transaction_cost(&c.transaction);
                acc
            });

        if state.balance < max_total_cost || state.transaction_count > min_nonce {
            // NOTE: We drop all the signed constraints containing such pre-confirmations
            // since at least one of them has been invalidated.
            tracing::warn!(
                %address,
                "Removing all signed constraints which contain such address pre-confirmations due to conflict with account state",
            );
            indexes = constraints_with_address.iter().map(|c| c.0).collect();
        }

        for index in indexes.into_iter().rev() {
            self.remove_constraints_at_index(index);
        }
    }
}

/// StateDiff tracks the intermediate changes to the state according to the block template.
#[derive(Debug, Default)]
pub struct StateDiff {
    /// Map of diffs per address. Each diff is a tuple of the nonce and balance diff
    /// that should be applied to the current state.
    diffs: HashMap<Address, (u64, U256)>,
}

impl StateDiff {
    /// Returns a tuple of the nonce and balance diff for the given address.
    /// The nonce diff should be added to the current nonce, the balance diff should be subtracted from
    /// the current balance.
    pub fn get_diff(&self, address: &Address) -> Option<(u64, U256)> {
        self.diffs.get(address).copied()
    }
}
