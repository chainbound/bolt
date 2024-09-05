use crate::telemetry::ApiMetrics;
use axum::{extract::Request, middleware::Next, response::IntoResponse};
use std::time::Instant;

/// Middleware to track server metrics for each request.
pub async fn track_server_metrics(req: Request, next: Next) -> impl IntoResponse {
    let path = req.uri().path().to_owned();
    let method = req.method().to_string();

    let start = Instant::now();
    let response = next.run(req).await;
    let latency = start.elapsed();
    let status = response.status().as_u16().to_string();

    ApiMetrics::observe_http_request(latency, method, path, status);

    response
}
