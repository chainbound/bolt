use clap::Parser;
use tracing::info;

mod json_rpc;
use json_rpc::start_server;

#[derive(Parser)]
struct Opts {
    #[clap(short, long, default_value = "8000")]
    port: u16,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting sidecar");

    let opts = Opts::parse();

    let shutdown_tx = start_server(opts.port).await?;

    tokio::signal::ctrl_c().await?;
    shutdown_tx.send(()).await.ok();

    Ok(())
}
