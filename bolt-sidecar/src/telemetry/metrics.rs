use std::time::Duration;

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use reth_primitives::TxType;

use crate::primitives::tx_type_str;

//  Counters ----------------------------------------------------------------
/// Counter for the total number of HTTP requests received.
const HTTP_REQUESTS_TOTAL: &str = "bolt_sidecar_http_requests_total";
/// Counter for the number of local blocks proposed.
const LOCAL_BLOCKS_PROPOSED: &str = "bolt_sidecar_local_blocks_proposed";
/// Counter for the number of remote blocks proposed.
const REMOTE_BLOCKS_PROPOSED: &str = "bolt_sidecar_remote_blocks_proposed";
/// Counter for the number of inclusion commitments received.
const INCLUSION_COMMITMENTS_RECEIVED: &str = "bolt_sidecar_inclusion_commitments_received";
/// Counter for the number of inclusion commitments accepted.
const INCLUSION_COMMITMENTS_ACCEPTED: &str = "bolt_sidecar_inclusion_commitments_accepted";
/// Counter for the number of transactions preconfirmed
const TRANSACTIONS_PRECONFIRMED: &str = "bolt_sidecar_transactions_preconfirmed";
/// Counter for the number of validation errors; to spot most the most common ones
const VALIDATION_ERRORS: &str = "bolt_sidecar_validation_errors";

//  Gauges ------------------------------------------------------------------
/// Gauge for the latest slot number
const LATEST_HEAD: &str = "bolt_sidecar_latest_head";

//  Histograms --------------------------------------------------------------
/// Histogram for the total duration of HTTP requests in seconds.
const HTTP_REQUESTS_DURATION_SECONDS: &str = "bolt_sidecar_http_requests_duration_seconds";

/// Metrics for the commitments API.
#[derive(Debug, Clone, Copy)]
pub struct ApiMetrics;

#[allow(missing_docs)]
impl ApiMetrics {
    pub fn describe_all() {
        // Counters
        describe_counter!(HTTP_REQUESTS_TOTAL, "Total number of HTTP requests received");
        describe_counter!(LOCAL_BLOCKS_PROPOSED, "Local blocks proposed");
        describe_counter!(REMOTE_BLOCKS_PROPOSED, "Remote blocks proposed");
        describe_counter!(INCLUSION_COMMITMENTS_ACCEPTED, "Inclusion commitments");
        describe_counter!(INCLUSION_COMMITMENTS_ACCEPTED, "Inclusion commitments accepted");
        describe_counter!(TRANSACTIONS_PRECONFIRMED, "Transactions preconfirmed");
        describe_counter!(VALIDATION_ERRORS, "Validation errors");

        // Gauges
        describe_gauge!(LATEST_HEAD, "Latest slot number");

        // Histograms
        describe_histogram!(
            HTTP_REQUESTS_DURATION_SECONDS,
            "Total duration of HTTP requests in seconds"
        );
    }

    /// Counters ----------------------------------------------------------------

    pub fn increment_total_http_requests(method: String, path: String, status: String) {
        counter!(
            HTTP_REQUESTS_DURATION_SECONDS,
            &[("method", method), ("path", path), ("status", status)]
        )
        .increment(1);
    }

    pub fn increment_local_blocks_proposed() {
        counter!(LOCAL_BLOCKS_PROPOSED).increment(1);
    }

    pub fn increment_remote_blocks_proposed() {
        counter!(REMOTE_BLOCKS_PROPOSED).increment(1);
    }

    pub fn increment_inclusion_commitments_received() {
        counter!(INCLUSION_COMMITMENTS_RECEIVED).increment(1);
    }

    pub fn increment_inclusion_commitments_accepted() {
        counter!(INCLUSION_COMMITMENTS_ACCEPTED).increment(1);
    }

    pub fn increment_transactions_preconfirmed(tx_type: TxType) {
        counter!(TRANSACTIONS_PRECONFIRMED, &[("type", tx_type_str(tx_type))]).increment(1);
    }

    pub fn increment_validation_errors(err_type: String) {
        counter!(VALIDATION_ERRORS, &[("type", err_type)]).increment(1);
    }

    /// Gauges ----------------------------------------------------------------

    pub fn set_latest_head(slot: u32) {
        gauge!(LATEST_HEAD).set(slot);
    }

    /// Mixed ----------------------------------------------------------------

    /// Observes the duration of an HTTP request by storing it in a histogram,
    /// and incrementing the total number of HTTP requests received.
    pub fn observe_http_request(duration: Duration, method: String, path: String, status: String) {
        let labels = [("method", method), ("path", path), ("status", status)];
        counter!(HTTP_REQUESTS_TOTAL, &labels).increment(1);
        histogram!(HTTP_REQUESTS_DURATION_SECONDS, &labels,).record(duration.as_secs_f64());
    }
}
