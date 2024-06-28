use std::time::Duration;

use bolt_sidecar::{
    builder::LocalBuilder,
    crypto::{
        bls::{Signer, SignerBLS},
        SignableBLS,
    },
    json_rpc::{self, api::ApiEvent},
    primitives::{
        BatchedSignedConstraints, ChainHead, ConstraintsMessage, FetchPayloadRequest,
        LocalPayloadFetcher, SignedConstraints,
    },
    spec::ConstraintsApi,
    start_builder_proxy,
    state::{
        fetcher::{StateClient, StateFetcher},
        ConsensusState, ExecutionState,
    },
    BuilderProxyConfig, Config, MevBoostClient,
};
use ethereum_consensus::crypto::SecretKey as BlsSecretKey;
use tokio::sync::mpsc;
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting sidecar");

    let config = Config::parse_from_cli()?;

    // TODO: support external signers
    // probably it's cleanest to have the Config parser initialize a generic Signer
    let signer = Signer::new(config.private_key.clone().unwrap());

    let state_client = StateClient::new(&config.execution_api_url, 8);
    let mevboost_client = MevBoostClient::new(&config.mevboost_url);

    let head = state_client.get_head().await?;
    let mut execution_state = ExecutionState::new(state_client, ChainHead::new(0, head)).await?;

    let (api_events, mut api_events_rx) = mpsc::channel(1024);
    let shutdown_tx = json_rpc::start_server(&config, api_events).await?;
    let consensus_state = ConsensusState::new(&config.beacon_api_url, &config.validator_indexes);

    let builder_proxy_config = BuilderProxyConfig {
        mevboost_url: config.mevboost_url,
        server_port: config.mevboost_proxy_port,
    };

    let (payload_tx, mut payload_rx) = mpsc::channel(16);
    let payload_fetcher = LocalPayloadFetcher::new(payload_tx);

    tracing::info!("JWT secret: {}", config.jwt_hex);

    let mut local_builder = LocalBuilder::new(
        BlsSecretKey::try_from(config.builder_private_key.to_bytes().as_ref())?,
        &config.execution_api_url,
        &config.engine_api_url,
        &config.jwt_hex,
        &config.beacon_api_url,
        config.fee_recipient,
    );

    tokio::spawn(async move {
        loop {
            if let Err(e) =
                start_builder_proxy(payload_fetcher.clone(), builder_proxy_config.clone()).await
            {
                tracing::error!("Builder API proxy failed: {:?}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    });

    // TODO: parallelize this
    loop {
        tokio::select! {
            Some(ApiEvent { request, response_tx }) = api_events_rx.recv() => {
                tracing::info!("Received commitment request: {:?}", request);

                let validator_index = match consensus_state.validate_request(&CommitmentRequest::Inclusion(request.clone())) {
                    Ok(index) => index,
                    Err(e) => {
                        tracing::error!("Failed to validate request: {:?}", e);
                        let _ = event.response.send(Err(ApiError::Custom(e.to_string())));
                        continue;
                    }
                };

                // if let Err(e) = execution_state
                //     .try_commit(&CommitmentRequest::Inclusion(request.clone()))
                //     .await
                // {
                //     tracing::error!("Failed to commit request: {:?}", e);
                //     let _ = response_tx.send(Err(ApiError::Custom(e.to_string())));
                //     continue;
                // }
                execution_state.commit_transaction(request.slot, request.tx.clone());

                tracing::info!(
                    tx_hash = %request.tx.hash(),
                    "Validation against execution state passed"
                );

                // parse the request into constraints and sign them with the sidecar signer
                let message = ConstraintsMessage::build(validator_index, request.slot, request.clone());

                let signature = signer.sign(&message.digest())?;
                let signed_constraints: BatchedSignedConstraints =
                    vec![SignedConstraints { message, signature: signature.to_string() }];

                // TODO: fix retry logic
                let max_retries = 5;
                let mut i = 0;
                'inner: while let Err(e) = mevboost_client
                    .submit_constraints(&signed_constraints)
                    .await
                {
                    tracing::error!(error = ?e, "Error submitting constraints, retrying...");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    i+=1;
                    if i >= max_retries {
                        break 'inner
                    }
                }

                let res = serde_json::to_value(signed_constraints).map_err(Into::into);
                let _ = response_tx.send(res).ok();
            }
            Some(FetchPayloadRequest { slot, response_tx }) = payload_rx.recv() => {
                tracing::info!(slot, "Received local payload request");

                let Some(template) = execution_state.get_block_template(slot) else {
                    tracing::warn!("No block template found for slot {slot} when requested");
                    let _ = response_tx.send(None);
                    continue;
                };

                // For fallback block building, we need to turn a block template into an actual SignedBuilderBid.
                // This will also require building the full ExecutionPayload that we want the proposer to commit to.
                // Once we have that, we need to send it as response to the validator via the pending get_header RPC call.
                // The validator will then call get_payload with the corresponding SignedBlindedBeaconBlock. We then need to
                // respond with the full ExecutionPayload inside the BeaconBlock (+ blobs if any).
                let payload_and_bid = match local_builder.build_new_local_payload(template.transactions).await {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::error!(err = ?e, "CRITICAL: Error while building local payload for slot {slot}");
                        let _ = response_tx.send(None);
                        continue;
                    }
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
