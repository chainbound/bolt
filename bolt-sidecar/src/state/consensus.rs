#![allow(missing_docs)]
#![allow(unused_variables)]
#![allow(missing_debug_implementations)]

use std::time::{Duration, Instant};

use beacon_api_client::{mainnet::Client, BlockId, ProposerDuty};
use ethereum_consensus::deneb::BeaconBlockHeader;
use reqwest::Url;

use super::CommitmentDeadline;
use crate::primitives::{CommitmentRequest, Slot};

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Beacon API error: {0}")]
    BeaconApiError(#[from] beacon_api_client::Error),
    #[error("Invalid slot: {0}")]
    InvalidSlot(Slot),
    #[error("Inclusion deadline exceeded")]
    DeadlineExceeded,
}

#[derive(Debug, Default)]
pub struct Epoch {
    pub value: u64,
    pub start_slot: Slot,
    pub proposer_duties: Vec<ProposerDuty>,
}

pub struct ConsensusState {
    beacon_api_client: Client,
    header: BeaconBlockHeader,
    epoch: Epoch,
    // The latest slot received from the beacon chain
    latest_slot: u64,
    // Timestamp of when the latest slot was received
    latest_slot_timestamp: Instant,
    /// The deadline (expressed in seconds) in the slot for which to
    /// stop accepting commitments.
    ///
    /// This is used to prevent the sidecar from accepting commitments
    /// which won't have time to be included by the PBS pipeline.
    // commitment_deadline: u64,
    pub commitment_deadline: CommitmentDeadline,
    pub commitment_deadline_duration: Duration,
}

impl ConsensusState {
    /// Create a new `ConsensusState` with the given beacon client HTTP URL.
    pub fn new(beacon_api_url: &str, commitment_deadline_duration: Duration) -> Self {
        let url = Url::parse(beacon_api_url).expect("valid beacon client URL");
        let beacon_api_client = Client::new(url);

        ConsensusState {
            beacon_api_client,
            header: BeaconBlockHeader::default(),
            epoch: Epoch::default(),
            latest_slot: 0,
            latest_slot_timestamp: Instant::now(),
            commitment_deadline: CommitmentDeadline::new(0, commitment_deadline_duration),
            commitment_deadline_duration,
        }
    }

    /// This function validates the state of the chain against a block. It checks 2 things:
    /// 1. The target slot is one of our proposer slots. (TODO)
    /// 2. The request hasn't passed the slot deadline.
    ///
    /// TODO: Integrate with the registry to check if we are registered.
    pub fn validate_request(&self, request: &CommitmentRequest) -> Result<(), ConsensusError> {
        let CommitmentRequest::Inclusion(req) = request;

        // Check if the slot is in the current epoch
        if req.slot < self.epoch.start_slot || req.slot >= self.epoch.start_slot + 32 {
            return Err(ConsensusError::InvalidSlot(req.slot));
        }

        // If the request is for the next slot, check if it's within the commitment deadline
        if req.slot == self.latest_slot + 1
            && self.latest_slot_timestamp + self.commitment_deadline_duration < Instant::now()
        {
            return Err(ConsensusError::DeadlineExceeded);
        }

        Ok(())
    }

    /// Update the latest head and fetch the relevant data from the beacon chain.
    pub async fn update_head(&mut self, head: u64) -> Result<(), ConsensusError> {
        // Reset the commitment deadline to start counting for the next slot.
        self.commitment_deadline =
            CommitmentDeadline::new(head + 1, self.commitment_deadline_duration);

        let update = self
            .beacon_api_client
            .get_beacon_header(BlockId::Slot(head))
            .await?;

        self.header = update.header.message;

        // Update the timestamp with current time
        self.latest_slot_timestamp = Instant::now();
        self.latest_slot = head;

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
}
