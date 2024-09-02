use commit_boost::prelude::*;
use eyre::Result;

mod constraints;
mod error;
mod proofs;
mod server;
mod types;

use server::{BuilderState, ConstraintsApi};
use types::ExtraConfig;

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>()?;
    let _guard = initialize_pbs_tracing_log();

    let custom_state = BuilderState::from_config(extra);
    let state = PbsState::new(pbs_config).with_data(custom_state);

    // TODO: metrics as below
    // PbsService::register_metric(Box::new(CHECK_RECEIVED_COUNTER.clone()));
    PbsService::init_metrics()?;

    PbsService::run::<BuilderState, ConstraintsApi>(state).await
}
