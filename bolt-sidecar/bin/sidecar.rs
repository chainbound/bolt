use bolt_sidecar::{config, json_rpc};

use clap::Parser;
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting sidecar");

    let opts = config::Opts::parse();
    let config = config::Config::try_from(opts)?;
    let shutdown_tx = json_rpc::start_server(config.rpc_port, config.private_key).await?;

    tokio::signal::ctrl_c().await?;
    shutdown_tx.send(()).await.ok();

    // High-level flow:
    // - Create block template
    // - Create state with client
    // - Subscribe to new blocks
    // - Update state on every new block
    // - Run template through state to invalidate commitments
    // - Accept new preconfs etc.

    Ok(())
}
