#![allow(missing_docs)]
#![allow(unused_variables)]
#![allow(missing_debug_implementations)]

use beacon_api_client::{mainnet::Client, BlockId};
use ethereum_consensus::deneb::BeaconBlockHeader;
use reqwest::Url;

use crate::primitives::ChainHead;

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("beacon API error: {0}")]
    BeaconApiError(#[from] beacon_api_client::Error),
}

pub struct ConsensusState {
    beacon_api_client: Client,
    header: BeaconBlockHeader,
}

impl ConsensusState {
    /// Create a new `ConsensusState` with the given beacon client HTTP URL.
    pub fn new(url: &str) -> Self {
        let url = Url::parse(url).expect("valid beacon client URL");
        let beacon_api_client = Client::new(url);

        Self {
            beacon_api_client,
            header: BeaconBlockHeader::default(),
        }
    }

    /// Update the latest head and fetch the relevant data from the beacon chain.
    pub async fn update_head(&mut self, head: ChainHead) -> Result<(), ConsensusError> {
        let update = self
            .beacon_api_client
            .get_beacon_header(BlockId::Slot(head.slot()))
            .await?;

        self.header = update.header.message;

        Ok(())
    }
}
