use metrics::{describe_counter, describe_gauge, describe_histogram};

/// Prometheus metrics for the Bolt Sidecar.
#[derive(Debug, Clone, Copy)]
pub enum BoltMetrics {
    //  Counters ----------------------------------------------------------------
    /// Counter for the total number of HTTP requests received.
    HttpRequestsTotal,
    /// Counter for the number of local blocks proposed.
    LocalBlocksProposed,
    /// Counter for the number of remote blocks proposed.
    RemoteBlocksProposed,
    /// Counter for the number of inclusion commitments received.
    InclusionCommitmentsReceived,
    /// Counter for the number of inclusion commitments accepted.
    InclusionCommitmentsAccepted,

    //  Gauges ------------------------------------------------------------------
    /// Gauge for the latest slot number
    LatestHead,

    //  Histograms --------------------------------------------------------------
    /// Histogram for the total duration of HTTP requests in seconds.
    HttpRequestsDurationSeconds,
}

impl BoltMetrics {
    /// Returns the name of the metric.
    pub const fn name(&self) -> &'static str {
        match self {
            BoltMetrics::LocalBlocksProposed => "local_blocks_proposed",
            BoltMetrics::RemoteBlocksProposed => "remote_blocks_proposed",
            BoltMetrics::InclusionCommitmentsReceived => "inclusion_commitments_received",
            BoltMetrics::InclusionCommitmentsAccepted => "inclusion_commitments_accepted",
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
        describe_counter!(BoltMetrics::LocalBlocksProposed.name(), "Local blocks proposed");
        describe_counter!(BoltMetrics::RemoteBlocksProposed.name(), "Remote blocks proposed");
        describe_counter!(
            BoltMetrics::InclusionCommitmentsReceived.name(),
            "Inclusion commitments"
        );
        describe_counter!(
            BoltMetrics::InclusionCommitmentsAccepted.name(),
            "Inclusion commitments accepted"
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
