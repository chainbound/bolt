use beacon_api_client::{mainnet::Client, Error, ProposerDuty};
use reqwest::Url;

pub struct LookaheadProvider {
    client: Client,
}

impl LookaheadProvider {
    pub fn new(url: &str) -> Self {
        Self {
            client: Client::new(Url::parse(url).unwrap()),
        }
    }

    /// Get the proposer duties for UPCOMING slots.
    pub async fn get_current_lookahead(&self) -> Result<Vec<ProposerDuty>, Error> {
        let current_slot = self
            .client
            .get_beacon_header_at_head()
            .await?
            .header
            .message
            .slot;

        let epoch = current_slot / 32;

        let (_, duties) = self.client.get_proposer_duties(epoch).await?;

        Ok(duties
            .into_iter()
            .filter(|d| d.slot > current_slot)
            .collect::<Vec<_>>())
    }
}
