use commit_boost::prelude::*;
use eyre::Result;

mod constraints;
mod error;
mod metrics;
mod proofs;
mod server;
mod types;

#[cfg(test)]
mod testutil;

use server::{BuilderState, ConstraintsApi};
use types::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, extra) = load_pbs_custom_config::<Config>()?;
    let _guard = initialize_pbs_tracing_log();

    let chain = pbs_config.chain;
    tracing::info!(?chain, "Starting bolt-boost with the following relays:");

    for relay in &pbs_config.relays {
        tracing::info!("ID: {} - URI: {}", relay.id, relay.config.entry.url);
    }

    let custom_state = BuilderState::from_config(extra);
    let state = PbsState::new(pbs_config).with_data(custom_state);

    metrics::init_metrics()?;

    PbsService::run::<BuilderState, ConstraintsApi>(state).await
}
