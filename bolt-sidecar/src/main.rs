#![doc = include_str!("../README.md")]
#![warn(
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    rustdoc::all
)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use std::str::FromStr;

use clap::Parser;
use eyre::Context;
use tracing::{info, warn};

mod json_rpc;
mod traits;

#[derive(Parser)]
struct Opts {
    /// Port to listen on for incoming JSON-RPC requests.
    #[clap(short = 'p', long, default_value = "8000")]
    port: u16,
    /// Private key to use for signing preconfirmation requests.
    #[clap(short = 'k', long)]
    private_key: String,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting BOLT sidecar");

    let opts = Opts::parse();

    let pk = secp256k1::SecretKey::from_str(&opts.private_key)
        .wrap_err("failed to parse private key")?;

    let shutdown_tx = json_rpc::start_server(opts.port, pk).await?;

    tokio::signal::ctrl_c().await?;
    shutdown_tx.send(()).await.ok();

    Ok(())
}
