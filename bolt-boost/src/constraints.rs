use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing::error;

use super::types::{ConstraintsMessage, ConstraintsWithProofData, HashTreeRoot};

/// A concurrent cache of constraints.
#[derive(Clone, Default, Debug)]
pub struct ConstraintsCache {
    cache: Arc<RwLock<HashMap<u64, Vec<ConstraintsWithProofData>>>>,
}

impl ConstraintsCache {
    pub fn new() -> Self {
        Self {
            cache: Default::default(),
        }
    }

    /// Checks if the constraints for the given slot conflict with the existing constraints.
    /// Will check for:
    /// - Multiple ToB constraints per slot
    /// - Duplicates of the same transaction per slot
    pub fn conflicts_with(&self, slot: &u64, constraints: &ConstraintsMessage) -> bool {
        if let Some(saved_constraints) = self.cache.read().unwrap().get(slot) {
            for saved_constraint in saved_constraints {
                // Only 1 ToB constraint per slot
                if constraints.top && saved_constraint.message.top {
                    return true;
                }

                // Check if the transactions are the same
                for tx in &constraints.transactions {
                    if saved_constraint
                        .message
                        .transactions
                        .iter()
                        .any(|existing| tx == existing)
                    {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Inserts the constraints for the given slot. Also decodes the raw transactions to save their
    /// transaction hashes and hash tree roots for later use. Will first check for conflicts, and return
    /// false if there are any.
    ///
    /// TODO: return Result instead of bool
    pub fn insert(&self, slot: u64, constraints: ConstraintsMessage) -> bool {
        if self.conflicts_with(&slot, &constraints) {
            return false;
        }

        let Ok(message_with_data) = ConstraintsWithProofData::try_from(constraints) else {
            error!("Failed decoding constraints, not inserting");
            return false;
        };

        if let Some(cs) = self.cache.write().unwrap().get_mut(&slot) {
            cs.push(message_with_data);
        } else {
            self.cache
                .write()
                .unwrap()
                .insert(slot, vec![message_with_data]);
        }

        true
    }

    /// Removes all constraints before the given slot.
    pub fn remove_before(&self, slot: u64) {
        self.cache.write().unwrap().retain(|k, _| *k >= slot);
    }

    /// Gets and removes the constraints for the given slot.
    pub fn remove(&self, slot: u64) -> Option<Vec<ConstraintsWithProofData>> {
        self.cache.write().unwrap().remove(&slot)
    }
}
