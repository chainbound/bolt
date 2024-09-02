use crate::telemetry::ApiMetricType;
use axum::{extract::Request, middleware::Next, response::IntoResponse};
use metrics::{counter, histogram};
use std::time::Instant;

/// Middleware to track server metrics for each request.
pub async fn track_server_metrics(req: Request, next: Next) -> impl IntoResponse {
    let path = req.uri().path().to_owned();
    let method = req.method().to_string();

    let start = Instant::now();
    let response = next.run(req).await;
    let latency = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    let labels = [("method", method), ("path", path), ("status", status)];

    counter!(ApiMetricType::HttpRequestsTotal.name(), &labels).increment(1);
    histogram!(ApiMetricType::HttpRequestsDurationSeconds.name(), &labels).record(latency);

    response
}
