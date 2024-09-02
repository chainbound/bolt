use std::time::Duration;

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use reth_primitives::TxType;

use crate::primitives::tx_type_str;

/// Metrics for the commitments API.
#[derive(Debug, Clone, Copy)]
pub struct ApiMetrics;

#[allow(missing_docs)]
impl ApiMetrics {
    pub fn start() {
        ApiMetricType::describe_all();
    }

    /// Counters ----------------------------------------------------------------

    pub fn increment_total_http_requests(method: String, path: String, status: String) {
        counter!(
            ApiMetricType::HttpRequestsTotal.name(),
            &[("method", method), ("path", path), ("status", status)]
        )
        .increment(1);
    }

    pub fn increment_local_blocks_proposed() {
        counter!(ApiMetricType::LocalBlocksProposed.name()).increment(1);
    }

    pub fn increment_remote_blocks_proposed() {
        counter!(ApiMetricType::RemoteBlocksProposed.name()).increment(1);
    }

    pub fn increment_inclusion_commitments_received() {
        counter!(ApiMetricType::InclusionCommitmentsReceived.name()).increment(1);
    }

    pub fn increment_inclusion_commitments_accepted() {
        counter!(ApiMetricType::InclusionCommitmentsAccepted.name()).increment(1);
    }

    pub fn increment_transactions_preconfirmed(tx_type: TxType) {
        counter!(ApiMetricType::TransactionsPreconfirmed.name(), &[("type", tx_type_str(tx_type))])
            .increment(1);
    }

    pub fn increment_validation_errors(err_type: String) {
        counter!(ApiMetricType::ValidationErrors.name(), &[("type", err_type)]).increment(1);
    }

    /// Gauges ----------------------------------------------------------------

    pub fn set_latest_head(slot: u32) {
        gauge!(ApiMetricType::LatestHead.name()).set(slot);
    }

    /// Mixed ----------------------------------------------------------------

    /// Observes the duration of an HTTP request by storing it in a histogram,
    /// and incrementing the total number of HTTP requests received.
    pub fn observe_http_request(duration: Duration, method: String, path: String, status: String) {
        let labels = [("method", method), ("path", path), ("status", status)];
        counter!(ApiMetricType::HttpRequestsTotal.name(), &labels).increment(1);
        histogram!(ApiMetricType::HttpRequestsDurationSeconds.name(), &labels,)
            .record(duration.as_secs_f64());
    }
}

/// Prometheus metrics for the Bolt Sidecar.
#[derive(Debug, Clone, Copy)]
enum ApiMetricType {
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

impl ApiMetricType {
    /// Returns the name of the metric.
    const fn name(&self) -> &'static str {
        match self {
            ApiMetricType::LocalBlocksProposed => "bolt_sidecar_local_blocks_proposed",
            ApiMetricType::RemoteBlocksProposed => "bolt_sidecar_remote_blocks_proposed",
            ApiMetricType::InclusionCommitmentsReceived => {
                "bolt_sidecar_inclusion_commitments_received"
            }
            ApiMetricType::InclusionCommitmentsAccepted => {
                "bolt_sidecar_inclusion_commitments_accepted"
            }
            ApiMetricType::HttpRequestsTotal => "bolt_sidecar_http_requests_total",
            ApiMetricType::LatestHead => "bolt_sidecar_latest_head",
            ApiMetricType::HttpRequestsDurationSeconds => {
                "bolt_sidecar_http_requests_duration_seconds"
            }
            ApiMetricType::TransactionsPreconfirmed => "bolt_sidecar_transactions_preconfirmed",
            ApiMetricType::ValidationErrors => "bolt_sidecar_validation_errors",
        }
    }

    /// Describes all metrics with a help string.
    fn describe_all() {
        // Counters
        describe_counter!(
            ApiMetricType::HttpRequestsTotal.name(),
            "Total number of HTTP requests received"
        );
        describe_counter!(ApiMetricType::LocalBlocksProposed.name(), "Local blocks proposed");
        describe_counter!(ApiMetricType::RemoteBlocksProposed.name(), "Remote blocks proposed");
        describe_counter!(
            ApiMetricType::InclusionCommitmentsReceived.name(),
            "Inclusion commitments"
        );
        describe_counter!(
            ApiMetricType::InclusionCommitmentsAccepted.name(),
            "Inclusion commitments accepted"
        );
        describe_counter!(
            ApiMetricType::TransactionsPreconfirmed.name(),
            "Transactions preconfirmed"
        );
        describe_counter!(ApiMetricType::ValidationErrors.name(), "Validation errors");

        // Gauges
        describe_gauge!(ApiMetricType::LatestHead.name(), "Latest slot number");

        // Histograms
        describe_histogram!(
            ApiMetricType::HttpRequestsDurationSeconds.name(),
            "Total duration of HTTP requests in seconds"
        );
    }
}
