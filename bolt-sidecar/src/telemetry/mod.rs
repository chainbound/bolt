use std::net::SocketAddr;

use eyre::{bail, Result};
use metrics_exporter_prometheus::PrometheusBuilder;
use tracing::info;
use tracing_subscriber::{
    fmt::Layer as FmtLayer, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
    Registry,
};

mod metrics;
pub use metrics::BoltMetrics;

/// Initialize the tracing stack and Prometheus metrics recorder.
///
/// **This function should be called at the beginning of the program.**
pub fn init_telemetry_stack(metrics_port: Option<u16>) -> Result<()> {
    // 1. Initialize tracing to stdout
    let std_layer = FmtLayer::default().with_writer(std::io::stdout).with_filter(
        EnvFilter::builder()
            .with_default_directive("bolt_sidecar=info".parse()?)
            .from_env_lossy()
            .add_directive("reqwest=error".parse()?)
            .add_directive("alloy_transport_http=error".parse()?),
    );
    Registry::default().with(std_layer).try_init()?;

    // 2. Initialize metrics recorder and start the Prometheus server
    if let Some(metrics_port) = metrics_port {
        let prometheus_addr = SocketAddr::from(([0, 0, 0, 0], metrics_port));
        let builder = PrometheusBuilder::new().with_http_listener(prometheus_addr);

        if let Err(e) = builder.install() {
            bail!("failed to install Prometheus recorder: {:?}", e);
        } else {
            info!(
                "Telemetry initialized. Serving Prometheus metrics at: http://{}",
                prometheus_addr
            );
        }

        BoltMetrics::describe_all();
    };

    Ok(())
}
