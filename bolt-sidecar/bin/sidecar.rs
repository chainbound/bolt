use clap::Parser;
use eyre::{bail, Result};
use tracing::info;

use bolt_sidecar::{telemetry::init_telemetry_stack, Opts, SidecarDriver};

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    if let Err(err) = init_telemetry_stack(opts.telemetry.metrics_port()) {
        bail!("Failed to initialize telemetry stack: {:?}", err)
    }

    info!(chain = opts.chain.name(), "Starting Bolt sidecar");

    if opts.constraint_signing.constraint_private_key.is_some() {
        match SidecarDriver::with_local_signer(&opts).await {
            Ok(driver) => driver.run_forever().await,
            Err(err) => {
                bail!("Failed to initialize the sidecar driver with local signer: {:?}", err)
            }
        }
    } else if opts.constraint_signing.commit_boost_signer_url.is_some() {
        match SidecarDriver::with_commit_boost_signer(&opts).await {
            Ok(driver) => driver.run_forever().await,
            Err(err) => {
                bail!("Failed to initialize the sidecar driver with commit boost: {:?}", err)
            }
        }
    } else {
        match SidecarDriver::with_keystore_signer(&opts).await {
            Ok(driver) => driver.run_forever().await,
            Err(err) => {
                bail!("Failed to initialize the sidecar driver with keystore signer: {:?}", err)
            }
        }
    }

    Ok(())
}
