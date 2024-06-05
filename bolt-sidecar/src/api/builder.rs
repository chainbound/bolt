use axum::{
    body::Body,
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

use crate::{client::mevboost::MevBoostClient, types::SignedBuilderBid};

/// A proxy server for the builder API. Forwards all requests to the target after interception.
pub struct BuilderProxyServer<T: BuilderApi> {
    proxy_target: T,
}

pub const STATUS_PATH: &str = "/eth/v1/builder/status";
pub const REGISTER_VALIDATORS_PATH: &str = "/eth/v1/builder/validators";
pub const GET_HEADER_PATH: &str = "/eth/v1/builder/header/:slot/:parent_hash/:pubkey";
pub const GET_HEADER_WITH_PROOFS_PATH: &str =
    "/eth/v1/builder/header_with_proofs/:slot/:parent_hash/:pubkey";
pub const GET_PAYLOAD_PATH: &str = "/eth/v1/builder/blinded_blocks";

#[derive(Debug, Deserialize)]
pub struct GetHeaderParams {
    pub slot: u64,
    pub parent_hash: Hash32,
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
}

impl<T: BuilderApi> BuilderProxyServer<T> {
    pub fn new(proxy_target: T) -> Self {
        Self { proxy_target }
    }

    pub async fn status(State(server): State<Arc<BuilderProxyServer<T>>>) -> StatusCode {
        server
            .proxy_target
            .status()
            .await
            .ok()
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

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

    pub async fn get_header(
        State(server): State<Arc<BuilderProxyServer<T>>>,
        Path(params): Path<GetHeaderParams>,
    ) -> Result<impl IntoResponse, impl IntoResponse> {
        server
            .proxy_target
            .get_header(params)
            .await
            .map(|header| Json(header))
            // TODO: convert errors to status codes
            .map_err(|e| StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub async fn get_payload(
        State(server): State<Arc<BuilderProxyServer<T>>>,
        req: Request<Body>,
    ) -> Result<impl IntoResponse, impl IntoResponse> {
        server
            .proxy_target
            .get_payload()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[async_trait::async_trait]
pub trait BuilderApi {
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/status>
    async fn status(&self) -> Result<StatusCode, Box<dyn std::error::Error>>;
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/registerValidator>
    async fn register_validators(
        &self,
        registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), Box<dyn std::error::Error>>;
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/getHeader>
    async fn get_header(
        &self,
        params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, Box<dyn std::error::Error>>;
    /// Implements: <https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock>
    async fn get_payload(&self) -> Result<Body, Box<dyn std::error::Error>>;
}

#[async_trait::async_trait]
pub trait ConstraintsApi: BuilderApi {
    async fn submit_constraints(
        &self,
        constraints: String,
    ) -> Result<(), Box<dyn std::error::Error>>;
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
