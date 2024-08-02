use bolt_sidecar::{Config, SidecarDriver};
use eyre::{bail, Result};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // TODO: improve telemetry setup (#116)
    tracing_subscriber::fmt::init();

    let config = Config::parse_from_cli()?;
    info!(chain = config.chain.name(), "Starting Bolt sidecar");

    match SidecarDriver::new(config).await {
        Ok(driver) => driver.run_forever().await,
        Err(err) => {
            tracing::error!(?err, "Failed to initialize the sidecar driver");
            bail!("Failed to initialize the sidecar driver: {:?}", err);
        }
    };

    Ok(())
}
