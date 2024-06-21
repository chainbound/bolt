use beacon_api_client::{mainnet::Client, Error, ProposerDuty};
use reqwest::Url;

pub struct LookaheadProvider {
    client: Client,
    url: String,
}

impl LookaheadProvider {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: Client::new(Url::parse(url).unwrap()),
        }
    }

    /// Get the proposer duties for UPCOMING slots.
    pub async fn get_current_lookahead(&self) -> Result<Vec<ProposerDuty>, Error> {
        tracing::info!("Getting current lookahead duties");
        // let current_slot = self
        //     .client
        //     .get_beacon_header_at_head()
        //     .await?
        //     .header
        //     .message
        //     .slot;
        let current_slot = get_slot(&self.url, "head")
            .await
            .expect("failed to get slot");

        let epoch = current_slot / 32;
        tracing::info!("Getting proposer duties for epoch: {}", epoch);

        let (_, duties) = self.client.get_proposer_duties(epoch).await?;

        Ok(duties
            .into_iter()
            .filter(|d| d.slot > current_slot)
            .collect::<Vec<_>>())
    }
}

async fn get_slot(beacon_url: &str, slot: &str) -> Result<u64, eyre::Error> {
    let url = format!("{}/eth/v1/beacon/headers/{}", beacon_url, slot);

    let res = reqwest::get(url).await?;
    let json: serde_json::Value = serde_json::from_str(&res.text().await?)?;

    let slot_num = eyre::Context::wrap_err(
        eyre::OptionExt::ok_or_eyre(
            eyre::OptionExt::ok_or_eyre(
                json.pointer("/data/header/message/slot"),
                "slot not found",
            )?
            .as_str(),
            "slot is not a string",
        )?
        .parse::<u64>(),
        "failed to parse slot",
    )?;

    Ok(slot_num)
}
