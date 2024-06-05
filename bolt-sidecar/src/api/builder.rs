use axum::{
    body::{to_bytes, Body},
    extract::{Path, Request, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use ethereum_consensus::{
    builder::SignedValidatorRegistration,
    primitives::{BlsPublicKey, Hash32},
};
use serde::Deserialize;
use std::sync::Arc;

use super::spec::{
    BuilderApi, ConstraintsApi, GET_HEADER_PATH, GET_PAYLOAD_PATH, REGISTER_VALIDATORS_PATH,
    STATUS_PATH,
};
use crate::{client::mevboost::MevBoostClient, types::SignedBuilderBid};

const MAX_BLINDED_BLOCK_LENGTH: usize = 1024 * 1024;

/// A proxy server for the builder API. Forwards all requests to the target after interception.
pub struct BuilderProxyServer<T: BuilderApi> {
    proxy_target: T,
}

#[derive(Debug, Deserialize)]
pub struct GetHeaderParams {
    pub slot: u64,
    pub parent_hash: Hash32,
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
}

impl<T: ConstraintsApi> BuilderProxyServer<T> {
    pub fn new(proxy_target: T) -> Self {
        Self { proxy_target }
    }

    /// Gets the status. Just forwards the request to mev-boost and returns the status.
    pub async fn status(State(server): State<Arc<BuilderProxyServer<T>>>) -> StatusCode {
        server
            .proxy_target
            .status()
            .await
            .ok()
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Registers the validators. Just forwards the request to mev-boost and returns the status.
    /// TODO: intercept this to register Bolt validators on-chain as well.
    pub async fn register_validators(
        State(server): State<Arc<BuilderProxyServer<T>>>,
        Json(registrations): Json<Vec<SignedValidatorRegistration>>,
    ) -> StatusCode {
        if server
            .proxy_target
            .register_validators(registrations)
            .await
            .is_ok()
        {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    /// Gets the header. NOTE: converts this request to a get_header_with_proofs request to the modified mev-boost.
    /// If we get an error response / timeout, we return the locally built block.
    pub async fn get_header(
        State(server): State<Arc<BuilderProxyServer<T>>>,
        Path(params): Path<GetHeaderParams>,
    ) -> Result<impl IntoResponse, impl IntoResponse> {
        // TODO: on error / timeout, return locally built block
        server
            .proxy_target
            .get_header_with_proofs(params)
            .await
            .map(Json)
            // TODO: convert errors to status codes
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub async fn get_payload(
        State(server): State<Arc<BuilderProxyServer<T>>>,
        req: Request<Body>,
    ) -> Result<impl IntoResponse, impl IntoResponse> {
        let body = req.into_body();
        let body_bytes = to_bytes(body, MAX_BLINDED_BLOCK_LENGTH)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        let signed_block =
            serde_json::from_slice(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

        server
            .proxy_target
            .get_payload(signed_block)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub struct BuilderProxyConfig {
    pub mev_boost_url: String,
    pub port: u16,
}

async fn start_builder_proxy(config: BuilderProxyConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mev_boost = MevBoostClient::new(config.mev_boost_url);
    let server = Arc::new(BuilderProxyServer::new(mev_boost));
    let router = Router::new()
        .route("/", get(index))
        .route(STATUS_PATH, get(BuilderProxyServer::status))
        .route(
            REGISTER_VALIDATORS_PATH,
            post(BuilderProxyServer::register_validators),
        )
        .route(GET_HEADER_PATH, get(BuilderProxyServer::get_header))
        .route(GET_PAYLOAD_PATH, post(BuilderProxyServer::get_payload))
        .with_state(server);

    // run it
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port)).await?;

    axum::serve(listener, router).await?;

    Ok(())
}

async fn index() -> Html<&'static str> {
    Html("Hello")
}
