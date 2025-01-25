use std::{
    fmt,
    time::{Duration, Instant},
};

use beacon_api_client::ProposerDuty;
use ethereum_consensus::{crypto::PublicKey as BlsPublicKey, phase0::mainnet::SLOTS_PER_EPOCH};
use tokio::join;
use tracing::debug;

use super::CommitmentDeadline;
use crate::{
    client::BeaconClient,
    primitives::{InclusionRequest, Slot},
    telemetry::ApiMetrics,
};

/// Consensus-related errors
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
#[non_exhaustive]
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

/// Represents an epoch in the beacon chain.
#[derive(Debug, Default)]
struct Epoch {
    /// The epoch number
    pub value: u64,
    /// The start slot of the epoch
    pub start_slot: Slot,
    /// The proposer duties of the current epoch.
    ///
    /// NOTE: if the `unsafe_lookhead` flag is enabled, then this field also contains
    /// the next epoch's proposer duties.
    pub proposer_duties: Vec<ProposerDuty>,
}

/// Represents the consensus state container for the sidecar.
///
/// This struct is responsible for managing the state of the beacon chain and the proposer duties,
/// including validating commitment requests and updating the state based on the latest slot.
pub struct ConsensusState {
    /// The beacon API client to fetch data from the beacon chain.
    beacon_api_client: BeaconClient,
    /// The current epoch and associated proposer duties.
    epoch: Epoch,
    // Timestamp of when the latest slot was received
    latest_slot_timestamp: Instant,
    // The latest slot received
    latest_slot: Slot,
    /// The deadline (expressed in seconds) in the slot for which to
    /// stop accepting commitments.
    ///
    /// This is used to prevent the sidecar from accepting commitments
    /// which won't have time to be included by the PBS pipeline.
    // commitment_deadline: u64,
    commitment_deadline: CommitmentDeadline,
    /// The duration of the commitment deadline.
    commitment_deadline_duration: Duration,
    /// If commitment requests should be validated also against the unsafe lookahead
    /// (i.e. the next epoch's proposer duties).
    ///
    /// It is considered unsafe because it is possible for the next epoch's duties to
    /// change if there are beacon chain deposits or withdrawals in the current epoch.
    unsafe_lookahead_enabled: bool,
}

impl fmt::Debug for ConsensusState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsensusState")
            .field("epoch", &self.epoch)
            .field("latest_slot", &self.latest_slot)
            .field("latest_slot_timestamp", &self.latest_slot_timestamp)
            .field("commitment_deadline", &self.commitment_deadline)
            .field("commitment_deadline_duration", &self.commitment_deadline_duration)
            .field("unsafe_lookahead_enabled", &self.unsafe_lookahead_enabled)
            .finish()
    }
}

impl ConsensusState {
    /// Create a new `ConsensusState` with the given configuration.
    pub fn new(
        beacon_api_client: BeaconClient,
        commitment_deadline_duration: Duration,
        unsafe_lookahead_enabled: bool,
    ) -> Self {
        Self {
            beacon_api_client,
            epoch: Epoch::default(),
            latest_slot: Default::default(),
            latest_slot_timestamp: Instant::now(),
            commitment_deadline: CommitmentDeadline::new(0, commitment_deadline_duration),
            commitment_deadline_duration,
            unsafe_lookahead_enabled,
        }
    }

    /// Validate an incoming commitment request against beacon chain data.
    /// The request is valid if:
    ///
    /// 1. The target slot is scheduled to be proposed by one of our validators.
    /// 2. The request hasn't passed the slot deadline.
    ///
    /// If the request is valid, return the validator public key for the target slot.
    pub fn validate_request(&self, req: &InclusionRequest) -> Result<BlsPublicKey, ConsensusError> {
        // Check if the slot is in the current epoch or next epoch (if unsafe lookahead is enabled)
        if req.slot < self.epoch.start_slot ||
            req.slot >= self.furthest_slot() ||
            req.slot <= self.latest_slot
        {
            return Err(ConsensusError::InvalidSlot(req.slot));
        }

        // If the request is for the next slot, check if it's within the commitment deadline
        if req.slot == self.latest_slot + 1 &&
            self.latest_slot_timestamp + self.commitment_deadline_duration < Instant::now()
        {
            return Err(ConsensusError::DeadlineExceeded);
        }

        // Find the validator pubkey for the given slot from the proposer duties
        self.find_validator_pubkey_for_slot(req.slot)
    }

    /// Wait for the commitment deadline to expire.
    pub async fn wait_commitment_deadline(&mut self) -> Option<u64> {
        self.commitment_deadline.wait().await
    }

    /// Update the latest head and fetch the relevant data from the beacon chain.
    pub async fn update_slot(&mut self, slot: u64) -> Result<(), ConsensusError> {
        debug!("Updating slot to {slot}");
        ApiMetrics::set_latest_head(slot as u32);

        // Reset the commitment deadline to start counting for the next slot.
        self.commitment_deadline =
            CommitmentDeadline::new(slot + 1, self.commitment_deadline_duration);

        // Update the timestamp with current time
        self.latest_slot_timestamp = Instant::now();
        self.latest_slot = slot;

        // Calculate the current value of epoch
        let epoch = slot / SLOTS_PER_EPOCH;

        // If the epoch has changed, update the proposer duties
        if epoch != self.epoch.value {
            debug!("Updating epoch to {epoch}");
            self.epoch.value = epoch;
            self.epoch.start_slot = epoch * SLOTS_PER_EPOCH;

            self.fetch_proposer_duties(epoch).await?;
        } else if self.epoch.proposer_duties.is_empty() {
            debug!(epoch, "No proposer duties found for current epoch, fetching...");
            // If the proposer duties are empty, fetch them
            self.fetch_proposer_duties(epoch).await?;
        }

        Ok(())
    }

    /// Fetch proposer duties for the given epoch and the next one if the unsafe lookahead flag is
    /// set
    async fn fetch_proposer_duties(&mut self, epoch: u64) -> Result<(), ConsensusError> {
        let duties = if self.unsafe_lookahead_enabled {
            let two_epoch_duties = join!(
                self.beacon_api_client.get_proposer_duties(epoch),
                self.beacon_api_client.get_proposer_duties(epoch + 1)
            );

            match two_epoch_duties {
                (Ok((_, mut duties)), Ok((_, next_duties))) => {
                    duties.extend(next_duties);
                    duties
                }
                (Err(e), _) | (_, Err(e)) => return Err(ConsensusError::BeaconApiError(e)),
            }
        } else {
            self.beacon_api_client.get_proposer_duties(epoch).await?.1
        };

        self.epoch.proposer_duties = duties;

        Ok(())
    }

    /// Finds the validator public key for the given slot from the proposer duties.
    fn find_validator_pubkey_for_slot(&self, slot: u64) -> Result<BlsPublicKey, ConsensusError> {
        self.epoch
            .proposer_duties
            .iter()
            .find(|&duty| duty.slot == slot)
            .map(|duty| duty.public_key.clone())
            .ok_or(ConsensusError::ValidatorNotFound)
    }

    /// Returns the furthest slot for which a commitment request is considered valid, whether in
    /// the current epoch or next epoch (if unsafe lookahead is enabled)
    fn furthest_slot(&self) -> u64 {
        self.epoch.start_slot +
            SLOTS_PER_EPOCH +
            if self.unsafe_lookahead_enabled { SLOTS_PER_EPOCH } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use beacon_api_client::BlockId;
    use reqwest::Url;
    use tracing::warn;

    use super::*;
    use crate::test_util::try_get_beacon_api_url;

    #[tokio::test]
    #[ignore = "TODO: fix"]
    async fn test_update_slot() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let commitment_deadline_duration = Duration::from_secs(1);

        let Some(url) = try_get_beacon_api_url().await else {
            warn!("skipping test: beacon API URL is not reachable");
            return Ok(());
        };

        let beacon_client = BeaconClient::new(Url::parse(url).unwrap());

        // Create the initial ConsensusState
        let mut state = ConsensusState {
            beacon_api_client: beacon_client,
            epoch: Epoch::default(),
            latest_slot: Default::default(),
            latest_slot_timestamp: Instant::now(),
            commitment_deadline: CommitmentDeadline::new(0, commitment_deadline_duration),
            commitment_deadline_duration,
            unsafe_lookahead_enabled: false,
        };

        // Update the slot to 32
        state.update_slot(32).await.unwrap();

        // Check values were updated correctly
        assert_eq!(state.latest_slot, 32);
        assert!(state.latest_slot_timestamp.elapsed().as_secs() < 1);
        assert_eq!(state.epoch.value, 1);
        assert_eq!(state.epoch.start_slot, 32);

        // Update the slot to 63, which should not update the epoch
        state.update_slot(63).await.unwrap();

        // Check values were updated correctly
        assert_eq!(state.latest_slot, 63);
        assert!(state.latest_slot_timestamp.elapsed().as_secs() < 1);
        assert_eq!(state.epoch.value, 1);
        assert_eq!(state.epoch.start_slot, 32);

        Ok(())
    }

    #[tokio::test]
    async fn test_fetch_proposer_duties() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let Some(url) = try_get_beacon_api_url().await else {
            warn!("skipping test: beacon API URL is not reachable");
            return Ok(());
        };

        let beacon_client = BeaconClient::new(Url::parse(url).unwrap());

        let commitment_deadline_duration = Duration::from_secs(1);

        // Create the initial ConsensusState
        let mut state = ConsensusState {
            beacon_api_client: beacon_client,
            epoch: Epoch::default(),
            latest_slot: Default::default(),
            latest_slot_timestamp: Instant::now(),
            commitment_deadline: CommitmentDeadline::new(0, commitment_deadline_duration),
            commitment_deadline_duration,
            // We test for both epochs
            unsafe_lookahead_enabled: true,
        };

        let epoch =
            state.beacon_api_client.get_beacon_header(BlockId::Head).await?.header.message.slot /
                SLOTS_PER_EPOCH;

        state.fetch_proposer_duties(epoch).await?;
        assert_eq!(state.epoch.proposer_duties.len(), SLOTS_PER_EPOCH as usize * 2);

        Ok(())
    }
}
