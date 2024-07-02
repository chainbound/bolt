#![allow(missing_docs)]
#![allow(unused_variables)]
#![allow(missing_debug_implementations)]

use beacon_api_client::{mainnet::Client, BlockId, ProposerDuty};
use ethereum_consensus::deneb::BeaconBlockHeader;
use reqwest::Url;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::primitives::{ChainHead, CommitmentRequest, Slot};

// The slot inclusion deadline in seconds
const INCLUSION_DEADLINE: u64 = 6;

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Beacon API error: {0}")]
    BeaconApiError(#[from] beacon_api_client::Error),
    #[error("Invalid slot: {0}")]
    InvalidSlot(Slot),
    #[error("Inclusion deadline exceeded")]
    DeadlineExceeded,
    #[error("Validator not found in the slot")]
    ValidatorNotFound,
}

pub struct Epoch {
    pub value: u64,
    pub start_slot: Slot,
    pub proposer_duties: Vec<ProposerDuty>,
}

pub struct ConsensusState {
    beacon_api_client: Client,
    header: BeaconBlockHeader,
    epoch: Epoch,
    // Timestamp when the current slot is received
    timestamp: u64,
    validator_indexes: Vec<u64>,
}

impl ConsensusState {
    /// Create a new `ConsensusState` with the given beacon client HTTP URL.
    pub fn new(url: &str, validator_indexes: &[u64]) -> Self {
        let url = Url::parse(url).expect("valid beacon client URL");
        let beacon_api_client = Client::new(url);

        ConsensusState {
            beacon_api_client,
            header: BeaconBlockHeader::default(),
            epoch: Epoch {
                value: 0,
                start_slot: 0,
                proposer_duties: vec![],
            },
            timestamp: 0,
            validator_indexes: validator_indexes.to_vec(),
        }
    }

    /// This function validates the state of the chain against a block. It checks 2 things:
    /// 1. The target slot is one of our proposer slots. (TODO)
    /// 2. The request hasn't passed the slot deadline.
    ///
    /// TODO: Integrate with the registry to check if we are registered.
    pub fn validate_request(&self, request: &CommitmentRequest) -> Result<u64, ConsensusError> {
        let CommitmentRequest::Inclusion(req) = request;

        // Check if the slot is in the current epoch
        if req.slot < self.epoch.start_slot || req.slot >= self.epoch.start_slot + 32 {
            return Err(ConsensusError::InvalidSlot(req.slot));
        }

        // Check if the request is within the slot inclusion deadline
        if self.timestamp + INCLUSION_DEADLINE < current_timestamp() {
            return Err(ConsensusError::DeadlineExceeded);
        }

        // Find the validator index for the given slot
        let validator_index = find_validator_index_for_slot(
            &self.validator_indexes,
            &self.epoch.proposer_duties,
            req.slot,
        )?;

        Ok(validator_index)
    }

    /// Update the latest head and fetch the relevant data from the beacon chain.
    pub async fn update_head(&mut self, head: ChainHead) -> Result<(), ConsensusError> {
        let update = self
            .beacon_api_client
            .get_beacon_header(BlockId::Slot(head.slot()))
            .await?;

        self.header = update.header.message;

        // Update the timestamp with current time
        self.timestamp = current_timestamp();

        // Get the current value of slot and epoch
        let slot = self.header.slot;
        let epoch = slot / 32;

        // If the epoch has changed, update the proposer duties
        if epoch != self.epoch.value {
            self.epoch.value = epoch;
            self.epoch.start_slot = epoch * 32;

            self.fetch_proposer_duties(epoch).await?;
        }

        Ok(())
    }

    /// Fetch proposer duties for the given epoch.
    async fn fetch_proposer_duties(&mut self, epoch: u64) -> Result<(), ConsensusError> {
        let duties = self.beacon_api_client.get_proposer_duties(epoch).await?;

        self.epoch.proposer_duties = duties.1;
        Ok(())
    }

    pub fn get_epoch(&self) -> &Epoch {
        &self.epoch
    }
}

/// Get the current timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Filters the proposer duties and returns the validator index for a given slot
/// if it doesn't exists then returns 0 by default.
pub fn find_validator_index_for_slot(
    validator_indexes: &[u64],
    proposer_duties: &[ProposerDuty],
    slot: u64,
) -> Result<u64, ConsensusError> {
    proposer_duties
        .iter()
        .find(|&duty| {
            duty.slot == slot && validator_indexes.contains(&(duty.validator_index as u64))
        })
        .map(|duty| duty.validator_index as u64)
        .ok_or(ConsensusError::ValidatorNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_api_client::ProposerDuty;

    #[test]
    fn test_filter_index() {
        let validator_indexes = vec![11, 22, 33];
        let proposer_duties = vec![
            ProposerDuty {
                public_key: Default::default(),
                slot: 1,
                validator_index: 11,
            },
            ProposerDuty {
                public_key: Default::default(),
                slot: 2,
                validator_index: 22,
            },
            ProposerDuty {
                public_key: Default::default(),
                slot: 3,
                validator_index: 33,
            },
        ];

        let result = find_validator_index_for_slot(&validator_indexes, &proposer_duties, 2);
        assert_eq!(result.unwrap(), 22);
    }
}
