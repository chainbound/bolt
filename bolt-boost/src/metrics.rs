use commit_boost::prelude::PbsService;
use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry, HistogramVec, IntCounterVec, IntGauge, Registry,
};

pub(crate) const TIMEOUT_ERROR_CODE_STR: &str = "555";
pub(crate) const GET_HEADER_WP_TAG: &str = "get_header_with_proofs";

pub(crate) fn init_metrics() -> eyre::Result<()> {
    // Initialize metrics
    PbsService::register_metric(Box::new(RELAY_LATENCY.clone()));
    PbsService::register_metric(Box::new(RELAY_STATUS_CODE.clone()));
    PbsService::register_metric(Box::new(RELAY_INVALID_BIDS.clone()));
    PbsService::register_metric(Box::new(CONSTRAINTS_CACHE_SIZE.clone()));

    PbsService::init_metrics()
}

lazy_static! {
    pub static ref BOLT_BOOST_METRICS: Registry =
        Registry::new_custom(Some("bolt_boost".to_string()), None).unwrap();

    /// The size of the constraints cache
    pub static ref CONSTRAINTS_CACHE_SIZE: IntGauge = register_int_gauge_with_registry!(
        "constraints_cache_size",
        "size of the constraints cache",
        BOLT_BOOST_METRICS
    )
    .unwrap();

    /// Latency by relay by endpoint
    pub static ref RELAY_LATENCY: HistogramVec = register_histogram_vec_with_registry!(
        "relay_latency_bolt",
        "HTTP latency by relay",
        &["endpoint", "relay_id"],
        BOLT_BOOST_METRICS
    )
    .unwrap();

    /// Status code received by relay by endpoint
    pub static ref RELAY_STATUS_CODE: IntCounterVec = register_int_counter_vec_with_registry!(
        "relay_status_code_total_bolt",
        "HTTP status code received by relay",
        &["http_status_code", "endpoint", "relay_id"],
        BOLT_BOOST_METRICS
    )
    .unwrap();

    /// Invalid bids per relay
    pub static ref RELAY_INVALID_BIDS: IntCounterVec = register_int_counter_vec_with_registry!(
        "relay_invalid_bids",
        "Invalid bids per relay (invalid proofs)",
        &["relay_id"],
        BOLT_BOOST_METRICS
    )
    .unwrap();

}
