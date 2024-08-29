use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct TelemetryOpts {
    /// The port on which to expose Prometheus metrics
    #[clap(short, long, env = "METRICS_PORT", default_value_t = 3300)]
    pub metrics_port: u16,
    #[clap(short, long, env = "USE_METRICS", default_value_t = true)]
    pub use_metrics: bool,
}
