//! Package `template` contains the functionality for building local block templates that can
//! be used as a fallback. It's also used to keep any intermediary state that is needed to simulate
//! new commitment requests.

// Should this be a trait?

use std::collections::HashMap;

use alloy_primitives::{Address, U256};
use alloy_rpc_types::Transaction;

use crate::common::max_transaction_cost;

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
    transactions: Vec<Transaction>,
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
    pub fn add_transaction(&mut self, transaction: Transaction) {
        let max_cost = max_transaction_cost(&transaction);

        // Update intermediate state
        self.state_diff
            .diffs
            .entry(transaction.from)
            .and_modify(|(nonce, balance)| {
                *nonce += 1;
                *balance += max_cost;
            })
            .or_insert((transaction.nonce, max_cost));

        self.transactions.push(transaction);
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
