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
use thiserror::Error;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use super::spec::{
    BuilderApiError, ConstraintsApi, GET_HEADER_PATH, GET_PAYLOAD_PATH, REGISTER_VALIDATORS_PATH,
    STATUS_PATH,
};
use crate::{
<<<<<<< HEAD
    client::constraints_client::ConstraintsClient,
=======
    client::mevboost::ConstraintClient,
>>>>>>> aa08f32 (feat(sidecar): constraints client init)
    primitives::{GetPayloadResponse, PayloadFetcher, SignedBuilderBid},
    telemetry::ApiMetrics,
};

const MAX_BLINDED_BLOCK_LENGTH: usize = 1024 * 1024;

/// TODO: determine value
const GET_HEADER_WITH_PROOFS_TIMEOUT: Duration = Duration::from_millis(500);

/// A proxy server for the builder API.
/// Forwards all requests to the target after interception.
pub struct BuilderProxyServer<T, P> {
    proxy_target: T,
    /// INVARIANT: This will be `Some` IFF we have signed a local header for the latest slot.
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
        Self { proxy_target, local_payload: Mutex::new(None), payload_fetcher }
    }

    /// Gets the status. Just forwards the request to constraints client and returns the status.
    pub async fn status(State(server): State<Arc<BuilderProxyServer<T, P>>>) -> StatusCode {
        let start = std::time::Instant::now();
        debug!("Received status request");

        let status = match server.proxy_target.status().await {
            Ok(status) => status,
            Err(error) => {
                error!(%error, "Failed to get status from constraints client");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        let elapsed = start.elapsed();
        debug!(?elapsed, "Returning status: {:?}", status);

        status
    }

    /// Registers the validators. Just forwards the request to constraints client
    /// and returns the status.
    ///
    /// TODO: intercept this to register Bolt validators on-chain as well.
    pub async fn register_validators(
        State(server): State<Arc<BuilderProxyServer<T, P>>>,
        Json(registrations): Json<Vec<SignedValidatorRegistration>>,
    ) -> Result<StatusCode, BuilderApiError> {
        debug!("Received register validators request");
        let response = server.proxy_target.register_validators(registrations).await;
        response.map(|_| StatusCode::OK)
    }

    /// Gets the header. NOTE: converts this request to a get_header_with_proofs
    /// request to the modified constraints client.
    ///
    /// In case of a builder or relay failure, we return the locally built block header
    /// and store the actual payload so we can return it later.
    pub async fn get_header(
        State(server): State<Arc<BuilderProxyServer<T, P>>>,
        Path(params): Path<GetHeaderParams>,
    ) -> Result<Json<VersionedValue<SignedBuilderBid>>, BuilderApiError> {
        let start = std::time::Instant::now();

        debug!("Received get_header request");
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
                    // Clear the local payload cache if we have a successful response
                    // By definition of `server.local_payload`, this will be `Some` IFF we have
                    // signed a local header
                    let mut local_payload = server.local_payload.lock();
                    *local_payload = None;

                    debug!(elapsed = ?start.elapsed(), "Returning signed builder bid");
                    return Ok(Json(header));
                }
            },
            Err(err) => BuilderApiError::Timeout(err),
        };

        // On ANY error, we fall back to locally built block
        warn!(slot, elapsed = ?start.elapsed(), err = ?err, "Proxy error, fetching local payload instead");

        let Some(payload_and_bid) = server.payload_fetcher.fetch_payload(slot).await else {
            // TODO: handle failure? In this case, we don't have a fallback block
            // which means we haven't made any commitments. This means the EL should
            // fallback to local block building.
            debug!("No local payload with commitments produced for slot {slot}");
            return Err(BuilderApiError::FailedToFetchLocalPayload(slot));
        };

        let hash = payload_and_bid.bid.message.header.block_hash.clone();
        let number = payload_and_bid.bid.message.header.block_number;
        info!(elapsed = ?start.elapsed(), %hash, "Fetched local payload for slot {slot}");

        {
            // Since we've signed a local header, set the payload for
            // the following `get_payload` request.
            let mut local_payload = server.local_payload.lock();
            *local_payload = Some(payload_and_bid.payload);
        }

        let versioned_bid = VersionedValue::<SignedBuilderBid> {
            version: Fork::Deneb,
            data: payload_and_bid.bid,
            meta: Default::default(),
        };

        info!(elapsed = ?start.elapsed(), %hash, number, ?versioned_bid, "Returning locally built header");
        Ok(Json(versioned_bid))
    }

    pub async fn get_payload(
        State(server): State<Arc<BuilderProxyServer<T, P>>>,
        req: Request<Body>,
    ) -> Result<Json<GetPayloadResponse>, BuilderApiError> {
        let start = std::time::Instant::now();
        debug!("Received get_payload request");

        let body_bytes =
            body::to_bytes(req.into_body(), MAX_BLINDED_BLOCK_LENGTH).await.map_err(|e| {
                error!(error = %e, "Failed to read request body");
                e
            })?;

        // Convert to signed blinded beacon block
        let signed_blinded_block = serde_json::from_slice::<SignedBlindedBeaconBlock>(&body_bytes)
            .map_err(|e| {
                error!(error = %e, "Failed to parse signed blinded block");
                e
            })?;

        // If we have a locally built payload, it means we signed a local header.
        // Return it and clear the cache.
        if let Some(local_payload) = server.local_payload.lock().take() {
            check_locally_built_payload_integrity(&signed_blinded_block, &local_payload)?;

            info!("Valid local block found, returning: {local_payload:?}");
            ApiMetrics::increment_local_blocks_proposed();

            return Ok(Json(local_payload));
        }

        // TODO: how do we deal with failures here? What if we submit the signed blinded block but
        // don't get a response? should we ignore the error or proceed with a local block
        // (highly risky -> equivocation risk)
        let payload = server
            .proxy_target
            .get_payload(signed_blinded_block)
            .await
            .map(Json)
            .map_err(|e| {
                error!(elapsed = ?start.elapsed(), error = %e, "Failed to get payload from constraints client");
                e
            })?;

        info!(elapsed = ?start.elapsed(), "Returning payload from constraints client");
        ApiMetrics::increment_remote_blocks_proposed();

        Ok(payload)
    }
}

/// Configuration for the builder proxy.
#[derive(Debug, Clone)]
pub struct BuilderProxyConfig {
    /// The URL of the target constraints client server.
    pub constraints_url: Url,
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
    info!(
        port = config.server_port,
        target = config.constraints_url.to_string(),
        "Starting builder proxy..."
    );

<<<<<<< HEAD
    let mev_boost = ConstraintsClient::new(config.constraints_url);
=======
    let mev_boost = ConstraintClient::new(config.mevboost_url);
>>>>>>> aa08f32 (feat(sidecar): constraints client init)
    let server = Arc::new(BuilderProxyServer::new(mev_boost, payload_fetcher));

    let router = Router::new()
        .route("/", get(index))
        .route(STATUS_PATH, get(BuilderProxyServer::status))
        .route(REGISTER_VALIDATORS_PATH, post(BuilderProxyServer::register_validators))
        .route(GET_HEADER_PATH, get(BuilderProxyServer::get_header))
        .route(GET_PAYLOAD_PATH, post(BuilderProxyServer::get_payload))
        .with_state(server);

    let addr = format!("0.0.0.0:{}", config.server_port);
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

async fn index() -> Html<&'static str> {
    Html("Hello")
}

#[derive(Error, Debug, Clone)]
pub enum LocalPayloadIntegrityError {
    #[error(
        "Locally built payload does not match signed header. 
        {field_name} mismatch: expected {expected}, have {have}"
    )]
    FieldMismatch { field_name: String, expected: String, have: String },
}

/// Helper macro to compare fields of the signed header and the local block.
macro_rules! assert_payload_fields_eq {
    ($expected:expr, $have:expr, $field_name:ident) => {
        if $expected != $have {
            error!(
                field_name = stringify!($field_name),
                expected = %$expected,
                have = %$have,
                "Local block does not match signed header"
            );
            return Err(LocalPayloadIntegrityError::FieldMismatch {
                field_name: stringify!($field_name).to_string(),
                expected: $expected.to_string(),
                have: $have.to_string(),
            });
        }
    };
}

/// Perform some integrity checks on the locally built payload.
/// This is to ensure that the beacon node will accept the header that was signed
/// when we submit the full payload.
#[inline]
fn check_locally_built_payload_integrity(
    signed_blinded_block: &SignedBlindedBeaconBlock,
    local_payload: &GetPayloadResponse,
) -> Result<(), LocalPayloadIntegrityError> {
    let header_signed_by_cl = &signed_blinded_block.message.body.execution_payload_header;
    let local_execution_payload = local_payload.execution_payload();

    assert_payload_fields_eq!(
        &header_signed_by_cl.block_hash,
        local_execution_payload.block_hash(),
        BlockHash
    );

    assert_payload_fields_eq!(
        header_signed_by_cl.block_number,
        local_execution_payload.block_number(),
        BlockNumber
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.state_root,
        local_execution_payload.state_root(),
        StateRoot
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.receipts_root,
        local_execution_payload.receipts_root(),
        ReceiptsRoot
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.prev_randao,
        local_execution_payload.prev_randao(),
        PrevRandao
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.gas_limit,
        &local_execution_payload.gas_limit(),
        GasLimit
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.gas_used,
        &local_execution_payload.gas_used(),
        GasUsed
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.timestamp,
        &local_execution_payload.timestamp(),
        Timestamp
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.extra_data,
        local_execution_payload.extra_data(),
        ExtraData
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.base_fee_per_gas,
        local_execution_payload.base_fee_per_gas(),
        BaseFeePerGas
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.parent_hash,
        local_execution_payload.parent_hash(),
        ParentHash
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.fee_recipient,
        local_execution_payload.fee_recipient(),
        FeeRecipient
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.logs_bloom,
        local_execution_payload.logs_bloom(),
        LogsBloom
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.blob_gas_used,
        &local_execution_payload.blob_gas_used().unwrap_or_default(),
        BlobGasUsed
    );

    assert_payload_fields_eq!(
        &header_signed_by_cl.excess_blob_gas,
        &local_execution_payload.excess_blob_gas().unwrap_or_default(),
        ExcessBlobGas
    );

    // TODO: Sanity check: recalculate transactions and withdrawals roots
    // and assert them against the header

    // TODO: Sanity check: verify the validator signature
    // signed_blinded_block.verify_signature()?;

    Ok(())
}
