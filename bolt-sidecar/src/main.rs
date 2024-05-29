#![doc = include_str!("../README.md")]
#![warn(missing_debug_implementations, missing_docs, rustdoc::all)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use clap::Parser;
use tracing::info;

mod bls;
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

    let opts = config::Opts::parse();

    let config = config::Config::try_from(opts)?;

    let shutdown_tx = start_server(config.rpc_port, config.private_key).await?;

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
