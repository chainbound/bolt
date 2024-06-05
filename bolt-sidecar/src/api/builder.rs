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
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

use super::spec::{
    BuilderApi, BuilderApiError, ConstraintsApi, GET_HEADER_PATH, GET_PAYLOAD_PATH,
    REGISTER_VALIDATORS_PATH, STATUS_PATH,
};
use crate::{client::mevboost::MevBoostClient, types::SignedBuilderBid};

const MAX_BLINDED_BLOCK_LENGTH: usize = 1024 * 1024;

/// TODO: determine value
const GET_HEADER_WITH_PROOFS_TIMEOUT: Duration = Duration::from_millis(500);

/// A proxy server for the builder API. Forwards all requests to the target after interception.
pub struct BuilderProxyServer<T: BuilderApi> {
    proxy_target: T,
    // TODO: fill with local payload when we fetch a payload
    // in failed get_header
    // This will only be some in case of a failed get_header
    local_payload: Mutex<Option<u64>>,
    /// The payload fetcher to get locally built payloads.
    payload_fetcher: LocalPayloadFetcher,
}

#[derive(Debug, Deserialize)]
pub struct GetHeaderParams {
    pub slot: u64,
    pub parent_hash: Hash32,
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
}

pub struct PayloadFetchParams {
    pub slot: u64,
    pub response: oneshot::Sender<Option<LocalPayload>>,
}

pub struct LocalPayload {
    pub bid: SignedBuilderBid,
    pub payload: u64,
}

pub struct LocalPayloadFetcher {
    tx: mpsc::Sender<PayloadFetchParams>,
}

impl LocalPayloadFetcher {
    pub async fn fetch_payload(&self, slot: u64) -> Option<LocalPayload> {
        let (tx, rx) = oneshot::channel();

        let fetch_params = PayloadFetchParams { slot, response: tx };

        self.tx.send(fetch_params).await.ok()?;

        rx.await.ok().flatten()
    }
}

impl<T: ConstraintsApi> BuilderProxyServer<T> {
    pub fn new(proxy_target: T, payload_fetcher: LocalPayloadFetcher) -> Self {
        Self {
            proxy_target,
            local_payload: Mutex::new(None),
            payload_fetcher,
        }
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
    ) -> Result<StatusCode, BuilderApiError> {
        server
            .proxy_target
            .register_validators(registrations)
            .await
            .map(|_| StatusCode::OK)
    }

    /// Gets the header. NOTE: converts this request to a get_header_with_proofs request to the modified mev-boost.
    /// If we get an error response / timeout, we return the locally built block.
    pub async fn get_header(
        State(server): State<Arc<BuilderProxyServer<T>>>,
        Path(params): Path<GetHeaderParams>,
    ) -> Result<Json<SignedBuilderBid>, BuilderApiError> {
        let slot = params.slot;

        match tokio::time::timeout(
            GET_HEADER_WITH_PROOFS_TIMEOUT,
            server.proxy_target.get_header_with_proofs(params),
        )
        .await
        {
            Ok(Ok(header)) => Ok(Json(header)),
            Ok(Err(_)) | Err(_) => {
                // On ANY error, we fall back to locally built block
                tracing::error!(
                    path = GET_HEADER_PATH,
                    slot,
                    "Proxy error, fetching local payload instead"
                );

                let payload = server
                    .payload_fetcher
                    .fetch_payload(slot)
                    .await
                    // TODO: handle failure? In this case, we don't have a fallback block
                    // which means we haven't made any commitments. This means the beacon client should
                    // fallback to local block building.
                    .ok_or(BuilderApiError::FailedToFetchLocalPayload(slot))?;

                {
                    // Set the payload for the following get_payload request
                    let mut local_payload = server.local_payload.lock().unwrap();
                    *local_payload = Some(payload.payload);
                }

                Ok(Json(payload.bid))
            }
        }

        // Err::<Json<SignedBuilderBid>, BuilderApiError>(
        //     BuilderApiError::NoValidatorsCouldBeRegistered,
        // )
    }

    pub async fn get_payload(
        State(server): State<Arc<BuilderProxyServer<T>>>,
        req: Request<Body>,
    ) -> Result<impl IntoResponse, BuilderApiError> {
        // TODO: on error / timeout, we fetch our locally built block and return it instead.
        let body = req.into_body();
        let body_bytes = to_bytes(body, MAX_BLINDED_BLOCK_LENGTH).await?;

        let signed_block = serde_json::from_slice(&body_bytes)?;

        server.proxy_target.get_payload(signed_block).await
    }
}

pub struct BuilderProxyConfig {
    pub mev_boost_url: String,
    pub port: u16,
}

async fn start_builder_proxy(
    payload_fetcher: LocalPayloadFetcher,
    config: BuilderProxyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mev_boost = MevBoostClient::new(config.mev_boost_url);
    let server = Arc::new(BuilderProxyServer::new(mev_boost, payload_fetcher));
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
