#![allow(missing_docs)]
#![allow(unused_variables)]
#![allow(missing_debug_implementations)]

use beacon_api_client::{mainnet::Client, BlockId, ProposerDuty};
use ethereum_consensus::deneb::BeaconBlockHeader;
use reqwest::Url;

use crate::primitives::ChainHead;

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("beacon API error: {0}")]
    BeaconApiError(#[from] beacon_api_client::Error),
}

pub struct Epoch {
    pub value: u64,
    pub start_slot: u64,
    pub proposer_duties: Vec<ProposerDuty>,
}

pub struct ConsensusState {
    beacon_api_client: Client,
    header: BeaconBlockHeader,
    epoch: Epoch,
}

impl ConsensusState {
    /// Create a new `ConsensusState` with the given beacon client HTTP URL.
    pub fn new(url: &str) -> Self {
        let url = Url::parse(url).expect("valid beacon client URL");
        let beacon_api_client = Client::new(url);

        Self {
            beacon_api_client,
            header: BeaconBlockHeader::default(),
            epoch: Epoch {
                value: 0,
                start_slot: 0,
                proposer_duties: vec![],
            },
        }
    }

    /// Update the latest head and fetch the relevant data from the beacon chain.
    pub async fn update_head(&mut self, head: ChainHead) -> Result<(), ConsensusError> {
        let update = self
            .beacon_api_client
            .get_beacon_header(BlockId::Slot(head.slot()))
            .await?;

        self.header = update.header.message;

        let slot = self.header.slot;
        let epoch = slot / 32;

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
