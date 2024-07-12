use axum::{
    body::{self, Body},
    extract::{Path, Request, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use beacon_api_client::VersionedValue;
use ethereum_consensus::{
    builder::SignedValidatorRegistration,
    deneb::mainnet::SignedBlindedBeaconBlock,
    primitives::{BlsPublicKey, Hash32},
    Fork,
};
use parking_lot::Mutex;
use reqwest::Url;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::net::TcpListener;

use super::spec::{
    BuilderApiError, ConstraintsApi, GET_HEADER_PATH, GET_PAYLOAD_PATH, REGISTER_VALIDATORS_PATH,
    STATUS_PATH,
};
use crate::{
    client::mevboost::MevBoostClient,
    primitives::{GetPayloadResponse, PayloadFetcher, SignedBuilderBid},
};

const MAX_BLINDED_BLOCK_LENGTH: usize = 1024 * 1024;

/// TODO: determine value
const GET_HEADER_WITH_PROOFS_TIMEOUT: Duration = Duration::from_millis(500);

/// A proxy server for the builder API.
/// Forwards all requests to the target after interception.
pub struct BuilderProxyServer<T, P> {
    proxy_target: T,
    // TODO: fill with local payload when we fetch a payload
    // in failed get_header
    // This will only be some in case of a failed get_header
    local_payload: Mutex<Option<GetPayloadResponse>>,
    /// The payload fetcher to get locally built payloads.
    payload_fetcher: P,
}

#[derive(Debug, Deserialize)]
pub struct GetHeaderParams {
    pub slot: u64,
    pub parent_hash: Hash32,
    #[serde(rename = "pubkey")]
    pub public_key: BlsPublicKey,
}

impl<T, P> BuilderProxyServer<T, P>
where
    T: ConstraintsApi,
    P: PayloadFetcher + Send + Sync,
{
    pub fn new(proxy_target: T, payload_fetcher: P) -> Self {
        Self {
            proxy_target,
            local_payload: Mutex::new(None),
            payload_fetcher,
        }
    }

    /// Gets the status. Just forwards the request to mev-boost and returns the status.
    pub async fn status(State(server): State<Arc<BuilderProxyServer<T, P>>>) -> StatusCode {
        let start = std::time::Instant::now();
        tracing::debug!("Received status request");

        let status = match server.proxy_target.status().await {
            Ok(status) => status,
            Err(error) => {
                tracing::error!(%error, "Failed to get status from mev-boost");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        let elapsed = start.elapsed();
        tracing::debug!(?elapsed, "Returning status: {:?}", status);

        status
    }

    /// Registers the validators. Just forwards the request to mev-boost
    /// and returns the status.
    ///
    /// TODO: intercept this to register Bolt validators on-chain as well.
    pub async fn register_validators(
        State(server): State<Arc<BuilderProxyServer<T, P>>>,
        Json(registrations): Json<Vec<SignedValidatorRegistration>>,
    ) -> Result<StatusCode, BuilderApiError> {
        let start = std::time::Instant::now();
        tracing::debug!("Received register validators request");

        let response = server.proxy_target.register_validators(registrations).await;

        let elapsed = start.elapsed();
        tracing::debug!(?elapsed, "Returning response: {:?}", response);

        response.map(|_| StatusCode::OK)
    }

    /// Gets the header. NOTE: converts this request to a get_header_with_proofs
    /// request to the modified mev-boost.
    ///
    /// In case of a builder or relay failure, we return the locally built block header
    /// and store the actual payload so we can return it later.
    pub async fn get_header(
        State(server): State<Arc<BuilderProxyServer<T, P>>>,
        Path(params): Path<GetHeaderParams>,
    ) -> Result<Json<VersionedValue<SignedBuilderBid>>, BuilderApiError> {
        let start = std::time::Instant::now();

        tracing::debug!("Received get_header request");
        let slot = params.slot;

        let err = match tokio::time::timeout(
            GET_HEADER_WITH_PROOFS_TIMEOUT,
            server.proxy_target.get_header_with_proofs(params),
        )
        .await
        {
            Ok(res) => match res {
                Err(builder_err) => builder_err,
                Ok(header) => {
                    tracing::debug!(elapsed = ?start.elapsed(), "Returning signed builder bid: {:?}", header);
                    return Ok(Json(header));
                }
            },
            Err(err) => BuilderApiError::Timeout(err),
        };

        // On ANY error, we fall back to locally built block
        tracing::warn!(slot, elapsed = ?start.elapsed(), err = ?err, "Proxy error, fetching local payload instead");

        let payload = match server.payload_fetcher.fetch_payload(slot).await {
            Some(payload) => {
                tracing::info!(elapsed = ?start.elapsed(), "Fetched local payload for slot {slot}");
                payload
            }
            None => {
                // TODO: handle failure? In this case, we don't have a fallback block
                // which means we haven't made any commitments. This means the beacon client should
                // fallback to local block building.
                tracing::error!("No local payload produced for slot {slot}");
                return Err(BuilderApiError::FailedToFetchLocalPayload(slot));
            }
        };

        let hash = payload.bid.message.header.block_hash.clone();
        let number = payload.bid.message.header.block_number;

        {
            // Set the payload for the following get_payload request
            let mut local_payload = server.local_payload.lock();
            *local_payload = Some(payload.payload);
        }

        let versioned_bid = VersionedValue::<SignedBuilderBid> {
            version: Fork::Deneb,
            data: payload.bid,
            // TODO: a more elegant way to do this? Can we avoid this meta field?
            meta: Default::default(),
        };

        tracing::info!(elapsed = ?start.elapsed(), %hash, number, "Returning locally built header");
        Ok(Json(versioned_bid))
    }

    pub async fn get_payload(
        State(server): State<Arc<BuilderProxyServer<T, P>>>,
        req: Request<Body>,
    ) -> Result<Json<GetPayloadResponse>, BuilderApiError> {
        let start = std::time::Instant::now();
        tracing::debug!("Received get_payload request");

        let body_bytes = body::to_bytes(req.into_body(), MAX_BLINDED_BLOCK_LENGTH)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to read request body");
                e
            })?;

        // Convert to signed blinded beacon block
        let signed_blinded_block = serde_json::from_slice::<SignedBlindedBeaconBlock>(&body_bytes)
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to parse signed blinded block");
                e
            })?;

        // If we have a locally built payload, return it and clear the cache.
        if let Some(payload) = server.local_payload.lock().take() {
            let requested_block = &signed_blinded_block
                .message
                .body
                .execution_payload_header
                .block_hash;

            // WARNING: this is an important check. If the local block does not match what the
            // beacon node has signed, we are at risk of equivocation and slashing.
            if payload.block_hash() != requested_block {
                tracing::error!(
                    expected = requested_block.to_string(),
                    have = payload.block_hash().to_string(),
                    "Local block hash does not match requested block hash"
                );

                return Err(BuilderApiError::InvalidLocalPayloadBlockHash {
                    expected: requested_block.to_string(),
                    have: payload.block_hash().to_string(),
                });
            };

            tracing::info!("Local block found, returning: {payload:?}");
            return Ok(Json(payload));
        }

        // TODO: how do we deal with failures here? What if we submit the signed blinded block but don't get a response?
        // should we ignore the error or proceed with a local block (highly risky -> equivocation risk)
        let payload = server
            .proxy_target
            .get_payload(signed_blinded_block)
            .await
            .map(Json)
            .map_err(|e| {
                tracing::error!(elapsed = ?start.elapsed(), error = %e, "Failed to get payload from mev-boost");
                e
            })?;

        tracing::debug!(elapsed = ?start.elapsed(), "Returning payload");

        Ok(payload)
    }
}

/// Configuration for the builder proxy.
#[derive(Debug, Clone)]
pub struct BuilderProxyConfig {
    /// The URL of the target mev-boost server.
    pub mevboost_url: Url,
    /// The port on which the builder proxy should listen.
    pub server_port: u16,
}

/// Start the builder proxy with the given payload fetcher and configuration.
pub async fn start_builder_proxy_server<P>(
    payload_fetcher: P,
    config: BuilderProxyConfig,
) -> eyre::Result<()>
where
    P: PayloadFetcher + Send + Sync + 'static,
{
    tracing::info!(
        port = config.server_port,
        target = config.mevboost_url.to_string(),
        "Starting builder proxy..."
    );

    let mev_boost = MevBoostClient::new(config.mevboost_url);
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

    let listener = TcpListener::bind(format!("0.0.0.0:{}", config.server_port)).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

async fn index() -> Html<&'static str> {
    Html("Hello")
}
