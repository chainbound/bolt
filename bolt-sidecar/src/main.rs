use clap::Parser;
use tracing::info;

mod client;
mod common;
mod config;
mod json_rpc;
mod pubsub;
mod state;
mod template;
mod types;
use json_rpc::start_server;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting sidecar");

    let opts = opts::Opts::parse();

    let config = Config::from(opts);

    let shutdown_tx = start_server(config.rpc_port, Some(config.private_key)).await?;

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
