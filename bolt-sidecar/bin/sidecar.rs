use std::time::Duration;

use bolt_sidecar::{
    crypto::{
        bls::{Signer, SignerBLS},
        SignableBLS,
    },
    json_rpc::{self, api::ApiError},
    primitives::{
        BatchedSignedConstraints, ChainHead, CommitmentRequest, ConstraintsMessage,
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

use tokio::sync::mpsc;
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting sidecar");

    let config = Config::parse_from_cli()?;

    // TODO: support external signers
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
            Some(event) = api_events_rx.recv() => {
                tracing::info!("Received commitment request: {:?}", event.request);
                let request = event.request;

                let validator_index = match consensus_state.validate_request(&CommitmentRequest::Inclusion(request.clone())) {
                    Ok(index) => index,
                    Err(e) => {
                        tracing::error!("Failed to validate request: {:?}", e);
                        let _ = event.response.send(Err(ApiError::Custom(e.to_string())));
                        continue;
                    }
                };

                if let Err(e) = execution_state
                    .try_commit(&CommitmentRequest::Inclusion(request.clone()))
                    .await
                {
                    tracing::error!("Failed to commit request: {:?}", e);
                    let _ = event.response.send(Err(ApiError::Custom(e.to_string())));
                    continue;
                }

                tracing::info!(
                    tx_hash = %request.tx.tx_hash(),
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
                while let Err(e) = mevboost_client
                    .submit_constraints(&signed_constraints)
                    .await
                {
                    tracing::error!(error = ?e, "Error submitting constraints, retrying...");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    i+=1;
                    if i >= max_retries {
                        break
                    }
                }
            }
            Some(request) = payload_rx.recv() => {
                tracing::info!("Received local payload request: {:?}", request);
                let Some(response) = execution_state.get_block_template(request.slot) else {
                    tracing::warn!("No block template found for slot {} when requested", request.slot);
                    let _ = request.response.send(None);
                    continue;
                };

                // For fallback block building, we need to turn a block template into an actual SignedBuilderBid.
                // This will also require building the full ExecutionPayload that we want the proposer to commit to.
                // Once we have that, we need to send it as response to the validator via the pending get_header RPC call.
                // The validator will then call get_payload with the corresponding SignedBlindedBeaconBlock. We then need to
                // respond with the full ExecutionPayload inside the BeaconBlock (+ blobs if any).

                let _ = request.response.send(None);
            }

            else => break,
        }
    }

    tokio::signal::ctrl_c().await?;
    shutdown_tx.send(()).await.ok();

    Ok(())
}
