use alloy::eips::eip2718::Eip2718Error;
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use tracing::error;

use crate::metrics;

use super::types::{ConstraintsMessage, ConstraintsWithProofData};

pub(crate) const MAX_CONSTRAINTS_PER_SLOT: usize = 128;

/// A concurrent cache of constraints.
#[derive(Clone, Default, Debug)]
pub struct ConstraintsCache {
    cache: Arc<RwLock<HashMap<u64, Vec<ConstraintsWithProofData>>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum Conflict {
    #[error("Multiple ToB constraints per slot")]
    TopOfBlock,
    #[error("Duplicate transaction in the same slot")]
    DuplicateTransaction,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Conflict(#[from] Conflict),
    #[error(transparent)]
    Decode(#[from] Eip2718Error),
    #[error("Max constraints per slot reached for slot {0}")]
    LimitReached(u64),
}

impl ConstraintsCache {
    pub fn new() -> Self {
        Self { cache: Default::default() }
    }

    /// Checks if the constraints for the given slot conflict with the existing constraints.
    /// Returns a [Conflict] in case of a conflict, None otherwise.
    ///
    /// # Possible conflicts
    /// - Multiple ToB constraints per slot
    /// - Duplicates of the same transaction per slot
    pub fn conflicts_with(&self, slot: &u64, constraints: &ConstraintsMessage) -> Option<Conflict> {
        if let Some(saved_constraints) = self.cache.read().get(slot) {
            for saved_constraint in saved_constraints {
                // Only 1 ToB constraint per slot
                if constraints.top && saved_constraint.message.top {
                    return Some(Conflict::TopOfBlock);
                }

                // Check if the transactions are the same
                for tx in &constraints.transactions {
                    if saved_constraint.message.transactions.iter().any(|existing| tx == existing) {
                        return Some(Conflict::DuplicateTransaction);
                    }
                }
            }
        }

        None
    }

    /// Inserts the constraints for the given slot. Also decodes the raw transactions to save their
    /// transaction hashes and hash tree roots for later use. Will first check for conflicts, and
    /// return an error if there are any.
    pub fn insert(&self, slot: u64, constraints: ConstraintsMessage) -> Result<(), Error> {
        if let Some(conflict) = self.conflicts_with(&slot, &constraints) {
            return Err(conflict.into());
        }

        let message_with_data = ConstraintsWithProofData::try_from(constraints)?;

        let mut cache = self.cache.write();
        if let Some(cs) = cache.get_mut(&slot) {
            if cs.len() >= MAX_CONSTRAINTS_PER_SLOT {
                error!("Max constraints per slot reached for slot {}", slot);
                return Err(Error::LimitReached(slot));
            }

            cs.push(message_with_data);
        } else {
            cache.insert(slot, vec![message_with_data]);
        }

        metrics::CONSTRAINTS_CACHE_SIZE.inc();

        Ok(())
    }

    /// Removes all constraints before the given slot.
    pub fn remove_before(&self, slot: u64) {
        self.cache.write().retain(|k, _| *k >= slot);
        metrics::CONSTRAINTS_CACHE_SIZE.set(self.total_constraints() as i64);
    }

    /// Gets and removes the constraints for the given slot.
    pub fn remove(&self, slot: u64) -> Option<Vec<ConstraintsWithProofData>> {
        self.cache.write().remove(&slot).inspect(|c| {
            metrics::CONSTRAINTS_CACHE_SIZE.sub(c.len() as i64);
        })
    }

    fn total_constraints(&self) -> usize {
        self.cache.read().values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use alloy::{primitives::bytes, rpc::types::beacon::BlsPublicKey};

    use super::*;

    #[test]
    fn test_constraints_cache_conflict() {
        let cache = ConstraintsCache::new();

        let tx = bytes!("f86481d8088302088a808090435b8080556001015a6161a8106001578718e5bb3abd109fa0ea5ad6553fb67639cec694e6697ac7b718bd7044fcdf5608fa64f6058e67db93a03953b5792d7d9ef7fc602fbe260e7a290760e8adc634f99ab1896e2c0d55afcb");

        let constraints = ConstraintsMessage {
            pubkey: BlsPublicKey::default(),
            slot: 0,
            top: false,
            transactions: vec![tx],
        };

        assert!(cache.conflicts_with(&0, &constraints).is_none());

        cache.insert(0, constraints.clone()).unwrap();

        assert!(matches!(
            cache.conflicts_with(&0, &constraints),
            Some(Conflict::DuplicateTransaction)
        ));

        assert!(cache.conflicts_with(&1, &constraints).is_none());
    }
}
