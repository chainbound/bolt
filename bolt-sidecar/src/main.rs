#![doc = include_str!("../README.md")]
#![warn(
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    rustdoc::all
)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use blst::min_pk::SecretKey;
use clap::Parser;
use tracing::{info, warn};

mod bls;
mod json_rpc;

#[derive(Parser)]
struct Opts {
    /// Port to listen on for incoming JSON-RPC requests.
    #[clap(short = 'p', long, default_value = "8000")]
    port: u16,
    /// BLS12_381 Private key to use for signing preconfirmation requests.
    #[clap(short = 'k', long)]
    bls_private_key: String,
    /// List of Bolt-compliant PBS relay endpoints to connect to.
    relays: Vec<String>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting BOLT sidecar");

    let opts = Opts::parse();

    let pk = SecretKey::from_bytes(&hex::decode(opts.bls_private_key)?)
        .map_err(|e| eyre::eyre!("failed to parse BLS private key: {:?}", e))?;

    if opts.relays.is_empty() {
        warn!(
            "No relay URLs provided, sidecar will not be able to submit preconfirmation requests"
        );
    } else {
        info!("Connecting to relays: {:?}", opts.relays);
    }

    let shutdown_tx = json_rpc::start_server(opts.port, pk, opts.relays).await?;

    tokio::signal::ctrl_c().await?;
    shutdown_tx.send(()).await.ok();

    Ok(())
}
