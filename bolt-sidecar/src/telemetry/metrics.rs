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
    /// Counter for the number of transactions preconfirmed
    TransactionsPreconfirmed,
    /// Counter for the number of validation errors, to spot most the most common ones
    ValidationErrors,

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
            BoltMetrics::LocalBlocksProposed => "bolt_sidecar_local_blocks_proposed",
            BoltMetrics::RemoteBlocksProposed => "bolt_sidecar_remote_blocks_proposed",
            BoltMetrics::InclusionCommitmentsReceived => {
                "bolt_sidecar_inclusion_commitments_received"
            }
            BoltMetrics::InclusionCommitmentsAccepted => {
                "bolt_sidecar_inclusion_commitments_accepted"
            }
            BoltMetrics::HttpRequestsTotal => "bolt_sidecar_http_requests_total",
            BoltMetrics::LatestHead => "bolt_sidecar_latest_head",
            BoltMetrics::HttpRequestsDurationSeconds => {
                "bolt_sidecar_http_requests_duration_seconds"
            }
            BoltMetrics::TransactionsPreconfirmed => "bolt_sidecar_transactions_preconfirmed",
            BoltMetrics::ValidationErrors => "bolt_sidecar_validation_errors",
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
        describe_counter!(
            BoltMetrics::TransactionsPreconfirmed.name(),
            "Transactions preconfirmed"
        );
        describe_counter!(BoltMetrics::ValidationErrors.name(), "Validation errors");

        // Gauges
        describe_gauge!(BoltMetrics::LatestHead.name(), "Latest slot number");

        // Histograms
        describe_histogram!(
            BoltMetrics::HttpRequestsDurationSeconds.name(),
            "Total duration of HTTP requests in seconds"
        );
    }
}
