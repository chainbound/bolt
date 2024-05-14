use std::str::FromStr;

use clap::Parser;
use eyre::Context;
use tracing::{info, warn};

mod json_rpc;
mod opts;
use json_rpc::start_server;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting sidecar");

    let opts = opts::Opts::parse();

    let pk = if let Some(pk) = opts.private_key {
        Some(secp256k1::SecretKey::from_str(&pk).context("Invalid private key")?)
    } else {
        warn!("No private key provided, preconfirmation requests will not be signed");
        None
    };

    let shutdown_tx = start_server(opts.port, pk).await?;

    tokio::signal::ctrl_c().await?;
    shutdown_tx.send(()).await.ok();

    Ok(())
}
