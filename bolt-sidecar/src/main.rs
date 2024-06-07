use std::str::FromStr;

use clap::Parser;
use eyre::Context;
use tracing::{info, warn};

mod json_rpc;
use json_rpc::start_server;

#[derive(Parser)]
struct Opts {
    /// Port to listen on for incoming JSON-RPC requests.
    #[clap(short = 'p', long, default_value = "8000")]
    port: u16,
    #[clap(short = 'u', long)]
    mevboost_url: Option<u16>,
    #[clap(short = 'u', long)]
    beacon_client_url: Option<u16>,
    /// Private key to use for signing preconfirmation requests.
    #[clap(short = 'k', long)]
    private_key: Option<String>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting sidecar");

    let opts = Opts::parse();

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
