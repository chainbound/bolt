use bolt_sidecar::telemetry::init_telemetry_stack;
use bolt_sidecar::{Config, SidecarDriver};
use eyre::{bail, Result};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let config = match Config::parse_from_cli() {
        Ok(config) => config,
        Err(err) => bail!("Failed to parse CLI arguments: {:?}", err),
    };

    let metrics_port = if !config.disable_metrics { Some(config.metrics_port) } else { None };
    if let Err(err) = init_telemetry_stack(metrics_port) {
        bail!("Failed to initialize telemetry stack: {:?}", err)
    }

    info!(chain = config.chain.name(), "Starting Bolt sidecar");
    match SidecarDriver::new(config).await {
        Ok(driver) => driver.run_forever().await,
        Err(err) => bail!("Failed to initialize the sidecar driver: {:?}", err),
    };

    Ok(())
}
