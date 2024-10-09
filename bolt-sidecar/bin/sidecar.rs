use bolt_sidecar::{telemetry::init_telemetry_stack, Opts, SidecarDriver};
use clap::Parser;
use eyre::{bail, Result};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    let metrics_port =
        if !opts.telemetry.disable_metrics { Some(opts.telemetry.metrics_port) } else { None };
    if let Err(err) = init_telemetry_stack(metrics_port) {
        bail!("Failed to initialize telemetry stack: {:?}", err)
    }

    info!(chain = opts.chain.name(), "Starting Bolt sidecar");

    if opts.signing.private_key.is_some() {
        match SidecarDriver::with_local_signer(&opts).await {
            Ok(driver) => driver.run_forever().await,
            Err(err) => bail!("Failed to initialize the sidecar driver: {:?}", err),
        }
    } else {
        match SidecarDriver::with_commit_boost_signer(&opts).await {
            Ok(driver) => driver.run_forever().await,
            Err(err) => {
                bail!("Failed to initialize the sidecar driver with commit boost: {:?}", err)
            }
        }
    }

    Ok(())
}
