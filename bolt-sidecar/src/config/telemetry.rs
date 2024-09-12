use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct TelemetryOpts {
    /// The port on which to expose Prometheus metrics
    #[clap(short, long, env = "BOLT_SIDECAR_METRICS_PORT", default_value_t = 3300)]
    pub metrics_port: u16,
    #[clap(short, long, env = "BOLT_SIDECAR_DISABLE_METRICS", default_value_t = false)]
    pub disable_metrics: bool,
}
