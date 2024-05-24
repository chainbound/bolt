//! Package `template` contains the functionality for building local block templates that can
//! be used as a fallback. It's also used to keep any intermediary state that is needed to simulate
//! new commitment requests.

// Should this be a trait?

use std::collections::HashMap;

use alloy_primitives::{Address, U256};

use crate::types::commitment::Commitment;

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
    transactions: Vec<Commitment>,
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
}

/// StateDiff tracks the intermediate changes to the state according to the block template.
#[derive(Debug, Default)]
pub struct StateDiff {
    diffs: HashMap<Address, (u64, U256)>,
}

impl StateDiff {
    pub fn get_diff(&self, address: &Address) -> Option<(u64, U256)> {
        self.diffs.get(address).copied()
    }
}
