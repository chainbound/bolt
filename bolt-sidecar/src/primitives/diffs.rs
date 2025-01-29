use std::collections::HashMap;

use alloy::primitives::{Address, U256};

/// StateDiff tracks the intermediate changes to the state according to the block template.
#[derive(Debug, Default)]
pub struct StateDiff {
    /// Map of diffs per address. Each diff is a tuple of the nonce and balance diff
    /// that should be applied to the current state.
    pub(crate) diffs: HashMap<Address, AccountDiff>,
}

impl StateDiff {
    /// Returns a tuple of the nonce and balance diff for the given address.
    /// The nonce diff should be added to the current nonce, the balance diff should be subtracted
    /// from the current balance.
    pub fn get_diff(&self, address: &Address) -> Option<AccountDiff> {
        self.diffs.get(address).copied()
    }
}

/// AccountDiff tracks the changes to an account's nonce and balance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AccountDiff {
    /// The nonce of the account.
    nonce: u64,
    /// The balance diff of the account.
    balance: BalanceDiff,
}

impl AccountDiff {
    /// Creates a new account diff with the given nonce and balance diff.
    pub fn new(nonce: u64, balance: BalanceDiff) -> Self {
        Self { nonce, balance }
    }

    /// Returns the nonce diff of the account.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Returns the balance diff of the account.
    pub fn balance(&self) -> BalanceDiff {
        self.balance
    }
}

/// A balance diff is a tuple of consisting of a balance increase and a balance decrease.
///
/// An `increase` should be _added_ to the current balance, while a `decrease` should be _subtracted_.
///
/// Example:
/// ```rs
/// let balance = U256::from(100);
/// let balance_diff = BalanceDiff::new(U256::from(50), U256::from(10));
/// assert_eq!(balance_diff.apply(balance), U256::from(140));
/// ```
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BalanceDiff {
    /// The balance increase.
    increase: U256,
    /// The balance decrease.
    decrease: U256,
}

impl BalanceDiff {
    /// Creates a new balance diff with the given increase and decrease.
    pub fn new(increase: U256, decrease: U256) -> Self {
        Self { increase, decrease }
    }

    /// Returns the increase of the balance diff.
    pub fn increase(&self) -> U256 {
        self.increase
    }

    /// Returns the decrease of the balance diff.
    pub fn decrease(&self) -> U256 {
        self.decrease
    }

    /// Applies the balance diff to the given balance.
    pub fn apply(&self, balance: U256) -> U256 {
        balance.saturating_add(self.increase).saturating_sub(self.decrease)
    }
}

/// A trait for applying a balance diff to a U256 balance.
pub trait BalanceDiffApplier {
    /// Applies the balance diff to the given balance.
    fn apply_diff(&self, diff: BalanceDiff) -> U256;
}

impl BalanceDiffApplier for U256 {
    fn apply_diff(&self, diff: BalanceDiff) -> U256 {
        self.saturating_add(diff.increase).saturating_sub(diff.decrease)
    }
}
