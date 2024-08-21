use metrics::{describe_counter, describe_gauge, describe_histogram};

/// Prometheus metrics for the Bolt Sidecar.
#[derive(Debug, Clone, Copy)]
pub enum BoltMetrics {
    //  Counters ----------------------------------------------------------------
    /// Counter for the total number of HTTP requests received.
    HttpRequestsTotal,

    //  Gauges ------------------------------------------------------------------
    /// Gauge for the latest slot number
    LatestHead,

    //  Histograms --------------------------------------------------------------
    /// Histogram for the total duration of HTTP requests in seconds.
    HttpRequestsDurationSeconds,
}

impl BoltMetrics {
    /// Returns the name of the metric.
    pub fn name(&self) -> &str {
        match self {
            BoltMetrics::HttpRequestsTotal => "http_requests_total",
            BoltMetrics::LatestHead => "latest_head",
            BoltMetrics::HttpRequestsDurationSeconds => "http_requests_duration_seconds",
        }
    }

    /// Describes all metrics with a help string.
    pub fn describe_all() {
        // Counters
        describe_counter!(
            BoltMetrics::HttpRequestsTotal.name(),
            "Total number of HTTP requests received"
        );

        // Gauges
        describe_gauge!(BoltMetrics::LatestHead.name(), "Latest slot number");

        // Histograms
        describe_histogram!(
            BoltMetrics::HttpRequestsDurationSeconds.name(),
            "Total duration of HTTP requests in seconds"
        );
    }
}
