use alloy::{
    eips::merge::EPOCH_SLOTS,
    primitives::{utils::format_ether, B256, U256},
    rpc::types::beacon::{relay::ValidatorRegistration, BlsPublicKey},
};
use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::{header::USER_AGENT, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use eyre::Result;
use futures::{future::join_all, stream::FuturesUnordered, StreamExt};
use serde::Serialize;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::time::sleep;
use tracing::{debug, error, info, warn, Instrument};

use cb_common::{
    config::PbsConfig,
    constants::APPLICATION_BUILDER_DOMAIN,
    pbs::{
        error::{PbsError, ValidationError},
        GetHeaderResponse, RelayClient, SignedExecutionPayloadHeader, EMPTY_TX_ROOT_HASH,
        HEADER_SLOT_UUID_KEY, HEADER_START_TIME_UNIX_MS,
    },
    signature::verify_signed_message,
    types::Chain,
    utils::{get_user_agent, get_user_agent_with_version, ms_into_slot, utcnow_ms},
};
use cb_pbs::{register_validator, BuilderApi, BuilderApiState, PbsState};

use crate::metrics::{
    GET_HEADER_WP_TAG, RELAY_INVALID_BIDS, RELAY_LATENCY, RELAY_STATUS_CODE, TIMEOUT_ERROR_CODE_STR,
};

use super::{
    constraints::ConstraintsCache,
    error::PbsClientError,
    proofs::verify_multiproofs,
    types::{
        Config, GetHeaderParams, GetHeaderWithProofsResponse, RequestConfig, SignedConstraints,
        SignedDelegation, SignedExecutionPayloadHeaderWithProofs, SignedRevocation,
    },
};

const SUBMIT_CONSTRAINTS_PATH: &str = "/constraints/v1/builder/constraints";
const DELEGATE_PATH: &str = "/constraints/v1/builder/delegate";
const REVOKE_PATH: &str = "/constraints/v1/builder/revoke";
const GET_HEADER_WITH_PROOFS_PATH: &str =
    "/eth/v1/builder/header_with_proofs/:slot/:parent_hash/:pubkey";

const TIMEOUT_ERROR_CODE: u16 = 555;

// Extra state available at runtime
#[derive(Clone)]
pub struct BuilderState {
    #[allow(unused)]
    config: Config,
    constraints: ConstraintsCache,
}

impl BuilderApiState for BuilderState {}

impl BuilderState {
    pub fn from_config(config: Config) -> Self {
        Self { config, constraints: ConstraintsCache::new() }
    }
}

/// An extended builder-API that implements the constraints-API as defined in
/// the spec: <https://chainbound.github.io/bolt-docs/api/builder>.
///
/// The added endpoints are defined in [extra_routes](ConstraintsApi::extra_routes).
pub struct ConstraintsApi;

#[async_trait]
impl BuilderApi<BuilderState> for ConstraintsApi {
    /// Register a validator with the builder.
    ///
    /// We intercept this call since it happens periodically and we use it to clean
    /// up old constraints.
    async fn register_validator(
        registrations: Vec<ValidatorRegistration>,
        req_headers: HeaderMap,
        state: PbsState<BuilderState>,
    ) -> eyre::Result<()> {
        let (slot, _) = state.get_slot_and_uuid();

        info!("Cleaning up constraints before slot {slot}");
        state.data.constraints.remove_before(slot);

        register_validator(registrations, req_headers, state).await
    }

    /// Gets the extra routes for supporting the constraints API as defined in
    /// the spec: <https://chainbound.github.io/bolt-docs/api/builder>.
    fn extra_routes() -> Option<Router<PbsState<BuilderState>>> {
        let mut router = Router::new();
        router = router.route(SUBMIT_CONSTRAINTS_PATH, post(submit_constraints));
        router = router.route(DELEGATE_PATH, post(delegate));
        router = router.route(REVOKE_PATH, post(revoke));
        router = router.route(GET_HEADER_WITH_PROOFS_PATH, get(get_header_with_proofs));
        Some(router)
    }
}

/// Submit signed constraints to the builder.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#constraints>
#[tracing::instrument(skip_all)]
async fn submit_constraints(
    State(state): State<PbsState<BuilderState>>,
    Json(constraints): Json<Vec<SignedConstraints>>,
) -> Result<impl IntoResponse, PbsClientError> {
    info!("Submitting {} constraints to relays", constraints.len());
    let (current_slot, _) = state.get_slot_and_uuid();

    // Save constraints for the slot to verify proofs against later.
    for signed_constraints in &constraints {
        let slot = signed_constraints.message.slot;

        // Only accept constraints for the current or next epoch.
        if slot > current_slot + EPOCH_SLOTS * 2 {
            warn!(slot, current_slot, "Constraints are too far in the future");
            return Err(PbsClientError::BadRequest);
        }

        if let Err(e) = state.data.constraints.insert(slot, signed_constraints.message.clone()) {
            error!(slot, error = %e, "Failed to save constraints");
            return Err(PbsClientError::BadRequest);
        }
    }

    post_request(state, SUBMIT_CONSTRAINTS_PATH, &constraints).await?;
    Ok(StatusCode::OK)
}

/// Delegate constraint submission rights to another BLS key.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#delegate>
#[tracing::instrument(skip_all)]
async fn delegate(
    State(state): State<PbsState<BuilderState>>,
    Json(delegations): Json<Vec<SignedDelegation>>,
) -> Result<impl IntoResponse, PbsClientError> {
    info!(count = %delegations.len(), "Delegating signing rights");
    post_request(state, DELEGATE_PATH, &delegations).await?;
    Ok(StatusCode::OK)
}

/// Revoke constraint submission rights from a BLS key.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#revoke>
#[tracing::instrument(skip_all)]
async fn revoke(
    State(state): State<PbsState<BuilderState>>,
    Json(revocations): Json<Vec<SignedRevocation>>,
) -> Result<impl IntoResponse, PbsClientError> {
    info!(count = %revocations.len(), "Revoking signing rights");
    post_request(state, REVOKE_PATH, &revocations).await?;
    Ok(StatusCode::OK)
}

/// Get a header with proofs for a given slot and parent hash.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#get_header_with_proofs>
#[tracing::instrument(skip_all, fields(slot = params.slot))]
async fn get_header_with_proofs(
    State(state): State<PbsState<BuilderState>>,
    Path(params): Path<GetHeaderParams>,
    req_headers: HeaderMap,
) -> Result<impl IntoResponse, PbsClientError> {
    let slot_uuid = state.get_or_update_slot_uuid(params.slot);

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    info!(ua, parent_hash=%params.parent_hash, validator_pubkey=%params.pubkey, ms_into_slot);

    let max_timeout_ms = state
        .pbs_config()
        .timeout_get_header_ms
        .min(state.pbs_config().late_in_slot_time_ms.saturating_sub(ms_into_slot));

    if max_timeout_ms == 0 {
        warn!(
            ms_into_slot,
            threshold = state.pbs_config().late_in_slot_time_ms,
            "late in slot, skipping relay requests"
        );

        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    // prepare headers, except for start time which is set in `send_one_get_header`
    let mut send_headers = HeaderMap::new();
    // TODO: error handling
    send_headers
        .insert(HEADER_SLOT_UUID_KEY, HeaderValue::from_str(&slot_uuid.to_string()).unwrap());
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers).unwrap());

    let relays = state.relays();
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(send_timed_get_header(
            params,
            relay.clone(),
            state.config.chain,
            state.pbs_config(),
            send_headers.clone(),
            ms_into_slot,
            max_timeout_ms,
        ));
    }

    let results = join_all(handles).await;
    let mut relay_bids = Vec::with_capacity(relays.len());
    let mut hash_to_proofs = HashMap::new();

    // Get and remove the constraints for this slot
    let maybe_constraints = state.data.constraints.remove(params.slot);

    for (i, res) in results.into_iter().enumerate() {
        let relay_id = relays[i].id.as_ref();

        match res {
            Ok(Some(res)) => {
                let root = res.data.header.message.header.transactions_root;

                let start = Instant::now();

                // If we have constraints to verify, do that here in order to validate the bid
                if let Some(ref constraints) = maybe_constraints {
                    // Verify the multiproofs and continue if not valid
                    if let Err(e) = verify_multiproofs(constraints, &res.data.proofs, root) {
                        error!(?e, relay_id, "Failed to verify multiproof, skipping bid");
                        RELAY_INVALID_BIDS.with_label_values(&[relay_id]).inc();
                        continue;
                    }

                    tracing::debug!("Verified multiproof in {:?}", start.elapsed());

                    // Save the proofs per block hash
                    hash_to_proofs
                        .insert(res.data.header.message.header.block_hash, res.data.proofs);
                }

                let vanilla_response =
                    GetHeaderResponse { version: res.version, data: res.data.header };

                relay_bids.push(vanilla_response)
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(?err, relay_id),
        }
    }

    if let Some(winning_bid) = state.add_bids(params.slot, relay_bids) {
        let header_with_proofs = GetHeaderWithProofsResponse {
            data: SignedExecutionPayloadHeaderWithProofs {
                // If there are no proofs, default to empty. This should never happen unless there
                // were no constraints to verify.
                proofs: hash_to_proofs
                    .get(&winning_bid.data.message.header.block_hash)
                    .cloned()
                    .unwrap_or_default(),
                header: winning_bid.data,
            },
            version: winning_bid.version,
        };

        Ok((StatusCode::OK, axum::Json(header_with_proofs)).into_response())
    } else {
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}

#[tracing::instrument(skip_all, name = "handler", fields(relay_id = relay.id.as_ref()))]
async fn send_timed_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    pbs_config: &PbsConfig,
    headers: HeaderMap,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
) -> Result<Option<GetHeaderWithProofsResponse>, PbsError> {
    let url = relay.get_url(&format!(
        "/eth/v1/builder/header_with_proofs/{}/{}/{}",
        params.slot, params.parent_hash, params.pubkey
    ))?;

    if relay.config.enable_timing_games {
        if let Some(target_ms) = relay.config.target_first_request_ms {
            // sleep until target time in slot

            let delay = target_ms.saturating_sub(ms_into_slot);
            if delay > 0 {
                debug!(target_ms, ms_into_slot, "TG: waiting to send first header request");
                timeout_left_ms = timeout_left_ms.saturating_sub(delay);
                sleep(Duration::from_millis(delay)).await;
            } else {
                debug!(target_ms, ms_into_slot, "TG: request already late enough in slot");
            }
        }

        if let Some(send_freq_ms) = relay.config.frequency_get_header_ms {
            let mut handles = Vec::new();

            debug!(send_freq_ms, timeout_left_ms, "TG: sending multiple header requests");

            loop {
                handles.push(tokio::spawn(
                    send_one_get_header(
                        params,
                        relay.clone(),
                        chain,
                        pbs_config.skip_sigverify,
                        pbs_config.min_bid_wei,
                        RequestConfig {
                            timeout_ms: timeout_left_ms,
                            url: url.clone(),
                            headers: headers.clone(),
                        },
                    )
                    .in_current_span(),
                ));

                if timeout_left_ms > send_freq_ms {
                    // enough time for one more
                    timeout_left_ms = timeout_left_ms.saturating_sub(send_freq_ms);
                    sleep(Duration::from_millis(send_freq_ms)).await;
                } else {
                    break;
                }
            }

            let results = join_all(handles).await;
            let mut n_headers = 0;

            if let Some((_, maybe_header)) = results
                .into_iter()
                .filter_map(|res| {
                    // ignore join error and timeouts, log other errors
                    res.ok().and_then(|inner_res| match inner_res {
                        Ok(maybe_header) => {
                            n_headers += 1;
                            Some(maybe_header)
                        }
                        Err(err) if err.is_timeout() => None,
                        Err(err) => {
                            error!(?err, "TG: error sending header request");
                            None
                        }
                    })
                })
                .max_by_key(|(start_time, _)| *start_time)
            {
                debug!(n_headers, "TG: received headers from relay");
                return Ok(maybe_header);
            } else {
                // all requests failed
                warn!("TG: no headers received");

                return Err(PbsError::RelayResponse {
                    error_msg: "no headers received".to_string(),
                    code: TIMEOUT_ERROR_CODE,
                });
            }
        }
    }

    // if no timing games or no repeated send, just send one request
    send_one_get_header(
        params,
        relay,
        chain,
        pbs_config.skip_sigverify,
        pbs_config.min_bid_wei,
        RequestConfig { timeout_ms: timeout_left_ms, url, headers },
    )
    .await
    .map(|(_, maybe_header)| maybe_header)
}

async fn send_one_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    skip_sigverify: bool,
    min_bid_wei: U256,
    mut req_config: RequestConfig,
) -> Result<(u64, Option<GetHeaderWithProofsResponse>), PbsError> {
    // the timestamp in the header is the consensus block time which is fixed,
    // use the beginning of the request as proxy to make sure we use only the
    // last one received
    let start_request_time = utcnow_ms();
    req_config.headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(start_request_time));

    let start_request = Instant::now();
    let res = match relay
        .client
        .get(req_config.url)
        .timeout(Duration::from_millis(req_config.timeout_ms))
        .headers(req_config.headers)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE
                .with_label_values(&[TIMEOUT_ERROR_CODE_STR, GET_HEADER_WP_TAG, &relay.id])
                .inc();
            return Err(err.into());
        }
    };

    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[GET_HEADER_WP_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());

    let code = res.status();
    RELAY_STATUS_CODE.with_label_values(&[code.as_str(), GET_HEADER_WP_TAG, &relay.id]).inc();

    let response_bytes = res.bytes().await?;
    if !code.is_success() {
        return Err(PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        });
    };

    if code == StatusCode::NO_CONTENT {
        debug!(
            ?code,
            latency = ?request_latency,
            response = ?response_bytes,
            "no header from relay"
        );
        return Ok((start_request_time, None));
    }

    let get_header_response: GetHeaderWithProofsResponse = serde_json::from_slice(&response_bytes)?;

    debug!(
        latency = ?request_latency,
        block_hash = %get_header_response.data.message.header.block_hash,
        value_eth = format_ether(get_header_response.data.message.value),
        "received new header"
    );

    validate_header(
        &get_header_response.data,
        chain,
        relay.pubkey(),
        params.parent_hash,
        skip_sigverify,
        min_bid_wei,
    )?;

    Ok((start_request_time, Some(get_header_response)))
}

fn validate_header(
    signed_header: &SignedExecutionPayloadHeader,
    chain: Chain,
    expected_relay_pubkey: BlsPublicKey,
    parent_hash: B256,
    skip_sig_verify: bool,
    minimum_bid_wei: U256,
) -> Result<(), ValidationError> {
    let block_hash = signed_header.message.header.block_hash;
    let received_relay_pubkey = signed_header.message.pubkey;
    let tx_root = signed_header.message.header.transactions_root;
    let value = signed_header.message.value;

    if block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash);
    }

    if parent_hash != signed_header.message.header.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            expected: parent_hash,
            got: signed_header.message.header.parent_hash,
        });
    }

    if tx_root == EMPTY_TX_ROOT_HASH {
        return Err(ValidationError::EmptyTxRoot);
    }

    if value <= minimum_bid_wei {
        return Err(ValidationError::BidTooLow { min: minimum_bid_wei, got: value });
    }

    if expected_relay_pubkey != received_relay_pubkey {
        return Err(ValidationError::PubkeyMismatch {
            expected: expected_relay_pubkey,
            got: received_relay_pubkey,
        });
    }

    if !skip_sig_verify {
        // Verify the signature against the builder domain.
        verify_signed_message(
            chain,
            &received_relay_pubkey,
            &signed_header.message,
            &signed_header.signature,
            APPLICATION_BUILDER_DOMAIN,
        )
        .map_err(ValidationError::Sigverify)?;
    }

    Ok(())
}

/// Send a POST request to all relays. Only returns an error if all of the requests fail.
async fn post_request<T>(
    state: PbsState<BuilderState>,
    path: &str,
    body: &T,
) -> Result<(), PbsClientError>
where
    T: Serialize,
{
    debug!("Sending POST request to {} relays", state.relays().len());
    // Forward constraints to all relays.
    let mut responses = FuturesUnordered::new();

    for relay in state.relays() {
        let url = relay.get_url(path).map_err(|_| PbsClientError::BadRequest)?;
        responses.push(relay.client.post(url).json(&body).send());
    }

    let mut success = false;
    while let Some(res) = responses.next().await {
        match res {
            Ok(response) => {
                let url = response.url().clone();
                let status = response.status();
                if status != StatusCode::OK {
                    let body = response.text().await.ok();
                    error!(%status, %url, "Failed to POST to relay: {body:?}");
                } else {
                    debug!(%url, "Successfully sent POST request to relay");
                    success = true;
                }
            }
            Err(e) => error!(error = ?e, "Failed to POST to relay"),
        }
    }

    if success {
        Ok(())
    } else {
        Err(PbsClientError::NoResponse)
    }
}
