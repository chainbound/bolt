use std::time::Duration;

use alloy_rpc_types_beacon::events::HeadEvent;
use tokio::sync::mpsc;

use bolt_sidecar::{
    crypto::{bls::Signer, SignableBLS, SignerBLS},
    json_rpc::api::{ApiError, ApiEvent},
    primitives::{
        CommitmentRequest, ConstraintsMessage, FetchPayloadRequest, LocalPayloadFetcher,
        SignedConstraints,
    },
    start_builder_proxy_server, start_rpc_server,
    state::{ConsensusState, ExecutionState, HeadTracker, StateClient},
    BeaconClient, BuilderProxyConfig, Config, ConstraintsApi, LocalBuilder, MevBoostClient,
};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::parse_from_cli()?;

    tracing::info!(chain = config.chain.name(), "Starting Bolt sidecar");

    // TODO: support external signers
    // probably it's cleanest to have the Config parser initialize a generic Signer
    let signer = Signer::new(config.private_key.clone().unwrap());

    let state_client = StateClient::new(config.execution_api_url.clone());
    let mut execution_state =
        ExecutionState::new(state_client, config.limits.max_commitments_per_slot).await?;

    let mevboost_client = MevBoostClient::new(config.mevboost_url.clone());
    let beacon_client = BeaconClient::new(config.beacon_api_url.clone());

    let (api_events, mut api_events_rx) = mpsc::channel(1024);
    let shutdown_tx = start_rpc_server(&config, api_events).await?;
    let mut consensus_state = ConsensusState::new(
        beacon_client.clone(),
        config.validator_indexes.clone(),
        config.chain.commitment_deadline(),
    );

    // TODO: this can be replaced with ethereum_consensus::clock::from_system_time()
    // but using beacon node events is easier to work on a custom devnet for now
    // (as we don't need to specify genesis time and slot duration)
    let mut head_tracker = HeadTracker::start(beacon_client);

    let builder_proxy_config = BuilderProxyConfig {
        mevboost_url: config.mevboost_url.clone(),
        server_port: config.mevboost_proxy_port,
    };

    let (payload_tx, mut payload_rx) = mpsc::channel(16);
    let payload_fetcher = LocalPayloadFetcher::new(payload_tx);

    let mut local_builder = LocalBuilder::new(&config);

    tokio::spawn(async move {
        if let Err(e) = start_builder_proxy_server(payload_fetcher, builder_proxy_config).await {
            tracing::error!("Builder API proxy failed: {:?}", e);
        }
    });

    // TODO: parallelize this
    loop {
        tokio::select! {
            Some(ApiEvent { request, response_tx }) = api_events_rx.recv() => {
                let start = std::time::Instant::now();

                let validator_index = match consensus_state.validate_request(&request) {
                    Ok(index) => index,
                    Err(e) => {
                        tracing::error!(err = ?e, "Failed to validate request");
                        let _ = response_tx.send(Err(ApiError::Custom(e.to_string())));
                        continue;
                    }
                };

                if let Err(e) = execution_state.validate_commitment_request(&request).await {
                    tracing::error!(err = ?e, "Failed to commit request");
                    let _ = response_tx.send(Err(ApiError::Custom(e.to_string())));
                    continue;
                };

                // TODO: match when we have more request types
                let CommitmentRequest::Inclusion(request) = request;
                tracing::info!(
                    elapsed = ?start.elapsed(),
                    tx_hash = %request.tx.hash(),
                    "Validation against execution state passed"
                );

                // parse the request into constraints and sign them with the sidecar signer
                let slot = request.slot;
                let message = ConstraintsMessage::build(validator_index, request);
                let signature = signer.sign(&message.digest())?.to_string();
                let signed_constraints = SignedConstraints { message, signature };

                execution_state.add_constraint(slot, signed_constraints.clone());

                let res = serde_json::to_value(signed_constraints).map_err(Into::into);
                let _ = response_tx.send(res).ok();
            },
            Ok(HeadEvent { slot, .. }) = head_tracker.next_head() => {
                tracing::info!(slot, "Received new head event");

                // We use None to signal that we want to fetch the latest EL head
                if let Err(e) = execution_state.update_head(None, slot).await {
                    tracing::error!(err = ?e, "Failed to update execution state head");
                }

                if let Err(e) = consensus_state.update_head(slot).await {
                    tracing::error!(err = ?e, "Failed to update consensus state head");
                }
            },
            Some(slot) = consensus_state.commitment_deadline.wait() => {
                tracing::info!(slot, "Commitment deadline reached, starting to build local block");

                let Some(template) = execution_state.remove_block_template(slot) else {
                    tracing::warn!("No block template found for slot {slot} when requested");
                    continue;
                };

                tracing::trace!(?template.signed_constraints_list, "Submitting constraints to MEV-Boost");

                // TODO: fix retry logic, and move this to separate task
                let max_retries = 5;
                let mut i = 0;
                'inner: while let Err(e) = mevboost_client
                    .submit_constraints(&template.signed_constraints_list)
                .await
                {
                    tracing::error!(err = ?e, "Error submitting constraints, retrying...");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    i+=1;
                    if i >= max_retries {
                        tracing::error!("Max retries reached while submitting to MEV-Boost");
                        break 'inner
                    }
                }

                if let Err(e) = local_builder.build_new_local_payload(&template).await {
                    tracing::error!(err = ?e, "CRITICAL: Error while building local payload at slot deadline for {slot}");
                };
            },
            Some(FetchPayloadRequest { slot, response_tx }) = payload_rx.recv() => {
                tracing::info!(slot, "Received local payload request");

                let Some(payload_and_bid) = local_builder.get_cached_payload() else  {
                        tracing::warn!("No local payload found for {slot}");
                        let _ = response_tx.send(None);
                        continue;
                };

                if let Err(e) = response_tx.send(Some(payload_and_bid)) {
                    tracing::error!(err = ?e, "Failed to send payload and bid in response channel");
                } else {
                    tracing::debug!("Sent payload and bid to response channel");
                }
            },
            Ok(_) = tokio::signal::ctrl_c() => {
                tracing::info!("Received SIGINT, shutting down...");
                shutdown_tx.send(()).await.ok();
                break;
            }
        }
    }

    Ok(())
}
