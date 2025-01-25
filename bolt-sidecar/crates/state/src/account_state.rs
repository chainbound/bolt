use std::ops::{Deref, DerefMut};

use alloy::primitives::Address;

use bolt_common::score_cache::ScoreCache;
use bolt_primitives::AccountState;
use bolt_telemetry::ApiMetrics;

const GET_SCORE: isize = 4;
const INSERT_SCORE: isize = 4;
const UPDATE_SCORE: isize = -1;

/// A scored cache for account states.
///
/// The cache is scored based on the number of times an account state is accessed.
/// In particular, there is a bonus when an account is read or inserted, because it means we've
/// received an inclusion preconfirmation requests.
///
/// Moreover, updates incur a penalty. That is because after we insert an account, we must keep
/// track of its updates during new blocks. The goal of this cache is to keep to most active
/// accounts in it.
#[derive(Debug, Default)]
pub struct AccountStateCache(
    pub ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, Address, AccountState>,
);

impl Deref for AccountStateCache {
    type Target = ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, Address, AccountState>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AccountStateCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AccountStateCache {
    /// Insert an account state into the cache, and update the metrics.
    pub fn insert(&mut self, address: Address, account_state: AccountState) {
        ApiMetrics::set_account_states(self.len());
        self.0.insert(address, account_state);
    }
}
