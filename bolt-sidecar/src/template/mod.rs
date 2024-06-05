//! Package `template` contains the functionality for building local block templates that can
//! be used as a fallback. It's also used to keep any intermediary state that is needed to simulate
//! new commitment requests.

// Should this be a trait?

use std::collections::HashMap;

use alloy_consensus::{TxEnvelope, TxType};
use alloy_primitives::{Address, U256};

use crate::{
    common::max_transaction_cost,
    primitives::{AccountState, TxInfo},
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
pub struct BlockTemplate {
    /// The state diffs per address given the list of commitments.
    state_diff: StateDiff,
    transactions: Vec<TxEnvelope>,
}

impl BlockTemplate {
    pub fn new() -> Self {
        Self {
            state_diff: StateDiff::default(),
            transactions: Vec::new(),
        }
    }

    pub fn state_diff(&self) -> &StateDiff {
        &self.state_diff
    }

    /// Adds a transaction to the block template and updates the state diff.
    pub fn add_transaction(&mut self, transaction: TxEnvelope) {
        let max_cost = max_transaction_cost(&transaction);

        // Update intermediate state
        self.state_diff
            .diffs
            .entry(transaction.from().expect("Passed validation"))
            .and_modify(|(nonce, balance)| {
                *nonce += 1;
                *balance += max_cost;
            })
            .or_insert((transaction.nonce(), max_cost));

        self.transactions.push(transaction);
    }

    /// Returns the length of the transactions in the block template.
    pub fn transactions_len(&self) -> usize {
        self.transactions.len()
    }

    /// Returns the blob count of the block template.
    pub fn blob_count(&self) -> usize {
        self.transactions.iter().fold(0, |mut acc, tx| {
            if tx.tx_type() == TxType::Eip4844 {
                acc += tx.blob_count();
            }

            acc
        })
    }

    /// Removes the transaction at the specified index and updates the state diff.
    fn remove_transaction_at_index(&mut self, index: usize) {
        let tx = self.transactions.remove(index);
        let max_cost = max_transaction_cost(&tx);

        // Update intermediate state
        self.state_diff
            .diffs
            .entry(tx.from().expect("Passed validation"))
            .and_modify(|(nonce, balance)| {
                *nonce = nonce.saturating_sub(1);
                *balance += max_cost;
            });
    }

    /// Retain removes any transactions that conflict with the given account state.
    pub fn retain(&mut self, address: Address, mut state: AccountState) {
        let mut indexes = Vec::new();

        for (index, tx) in self.transactions.iter().enumerate() {
            let max_cost = max_transaction_cost(tx);
            if tx.from().unwrap() == address
                && (state.balance < max_cost || state.transaction_count > tx.nonce())
            {
                tracing::trace!(
                    %address,
                    "Removing transaction at index {} due to conflict with account state",
                    index
                );

                indexes.push(index);
                // Continue to the next iteration, not updating the state
                continue;
            }

            // Update intermediary state for next transaction (if the tx was not removed)
            state.balance -= max_cost;
            state.transaction_count += 1;
        }

        // Remove transactions that conflict with the account state. We start in reverse
        // order to avoid invalidating the indexes.
        for index in indexes.into_iter().rev() {
            self.remove_transaction_at_index(index);
        }
    }
}

/// StateDiff tracks the intermediate changes to the state according to the block template.
#[derive(Debug, Default)]
pub struct StateDiff {
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
