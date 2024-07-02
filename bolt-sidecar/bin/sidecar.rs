use std::time::Duration;

use alloy_rpc_types_beacon::events::HeadEvent;
use ethereum_consensus::crypto::SecretKey as BlsSecretKey;
use tokio::sync::mpsc;
use tracing::info;

use bolt_sidecar::{
    builder::LocalBuilder,
    crypto::{bls::Signer, SignableBLS, SignerBLS},
    json_rpc::{
        self,
        api::{ApiError, ApiEvent},
    },
    primitives::{
        CommitmentRequest, ConstraintsMessage, FetchPayloadRequest, LocalPayloadFetcher,
        SignedConstraints,
    },
    spec::ConstraintsApi,
    start_builder_proxy,
    state::{ConsensusState, ExecutionState, HeadTracker, StateClient},
    BuilderProxyConfig, Config, MevBoostClient,
};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting sidecar");

    let config = Config::parse_from_cli()?;

    // TODO: support external signers
    // probably it's cleanest to have the Config parser initialize a generic Signer
    let signer = Signer::new(config.private_key.clone().unwrap());

    let state_client = StateClient::new(&config.execution_api_url);
    let mut execution_state = ExecutionState::new(state_client).await?;

    let mevboost_client = MevBoostClient::new(&config.mevboost_url);

    let (api_events, mut api_events_rx) = mpsc::channel(1024);
    let shutdown_tx = json_rpc::start_server(&config, api_events).await?;
    let mut consensus_state = ConsensusState::new(
        &config.beacon_api_url,
        &config.validator_indexes,
        config.commitment_deadline,
    );

    // TODO: this can be replaced with ethereum_consensus::clock::from_system_time()
    // but using beacon node events is easier to work on a custom devnet for now
    // (as we don't need to specify genesis time and slot duration)
    let mut head_tracker = HeadTracker::start(&config.beacon_api_url);

    let builder_proxy_config = BuilderProxyConfig {
        mevboost_url: config.mevboost_url,
        server_port: config.mevboost_proxy_port,
    };

    let (payload_tx, mut payload_rx) = mpsc::channel(16);
    let payload_fetcher = LocalPayloadFetcher::new(payload_tx);

    let mut local_builder = LocalBuilder::new(
        BlsSecretKey::try_from(config.builder_private_key.to_bytes().as_ref())?,
        &config.execution_api_url,
        &config.engine_api_url,
        &config.jwt_hex,
        &config.beacon_api_url,
        config.fee_recipient,
    );

    tokio::spawn(async move {
        if let Err(e) = start_builder_proxy(payload_fetcher, builder_proxy_config).await {
            tracing::error!("Builder API proxy failed: {:?}", e);
        }
    });

    // TODO: parallelize this
    loop {
        tokio::select! {
            Some(ApiEvent { request, response_tx }) = api_events_rx.recv() => {
                tracing::info!("Received commitment request: {:?}", request);

                let validator_index = match consensus_state.validate_request(&request) {
                    Ok(index) => index,
                    Err(e) => {
                        tracing::error!("Failed to validate request: {:?}", e);
                        let _ = response_tx.send(Err(ApiError::Custom(e.to_string())));
                        continue;
                    }
                };

                // if let Err(e) = execution_state
                //     .try_commit(&request)
                //     .await
                // {
                //     tracing::error!("Failed to commit request: {:?}", e);
                //     let _ = response_tx.send(Err(ApiError::Custom(e.to_string())));
                //     continue;
                // }

                // TODO: match when we have more request types
                let CommitmentRequest::Inclusion(request) = request;

                execution_state.commit_transaction(request.slot, request.tx.clone());

                tracing::info!(
                    tx_hash = %request.tx.hash(),
                    "Validation against execution state passed"
                );

                // parse the request into constraints and sign them with the sidecar signer
                let message = ConstraintsMessage::build(validator_index, request.slot, request);

                let signature = signer.sign(&message.digest())?.to_string();
                let signed_constraints = vec![SignedConstraints { message, signature }];

                // TODO: fix retry logic
                let max_retries = 5;
                let mut i = 0;
                'inner: while let Err(e) = mevboost_client
                    .submit_constraints(&signed_constraints)
                    .await
                {
                    tracing::error!(err = ?e, "Error submitting constraints, retrying...");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    i+=1;
                    if i >= max_retries {
                        break 'inner
                    }
                }

                let res = serde_json::to_value(signed_constraints).map_err(Into::into);
                let _ = response_tx.send(res).ok();
            },
            Ok(HeadEvent { slot, .. }) = head_tracker.next_head() => {
                tracing::info!(slot, "Received new head event");

                // We use None to signal that we want to fetch the latest EL head
                if let Err(e) = execution_state.update_head(None).await {
                    tracing::error!(err = ?e, "Failed to update execution state head");
                }

                if let Err(e) = consensus_state.update_head(slot).await {
                    tracing::error!(err = ?e, "Failed to update consensus state head");
                }
            },
            Some(slot) = consensus_state.commitment_deadline.wait() => {
                tracing::info!(slot, "Commitment deadline reached, starting to build local block");

                let Some(template) = execution_state.get_block_template(slot) else {
                    tracing::warn!("No block template found for slot {slot} when requested");
                    continue;
                };

                if let Err(e) = local_builder.build_new_local_payload(template.transactions).await {
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
