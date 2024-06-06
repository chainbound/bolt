use bolt_sidecar::{
    config::{Config, Opts},
    crypto::bls::{from_bls_signature_to_consensus_signature, BLSSigner},
    json_rpc::{api::ApiError, start_server},
    primitives::{
        constraint::{BatchedSignedConstraints, ConstraintsMessage, SignedConstraints},
        ChainHead, CommitmentRequest, LocalPayloadFetcher, NoopPayloadFetcher,
    },
    spec::ConstraintsApi,
    start_builder_proxy,
    state::{
        fetcher::{StateClient, StateFetcher},
        ExecutionState,
    },
    BuilderProxyConfig, MevBoostClient,
};

use clap::Parser;
use tokio::sync::mpsc;
use tracing::info;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting sidecar");

    let opts = Opts::parse();
    let config = Config::try_from(opts)?;

    let (api_events, mut api_events_rx) = mpsc::channel(1024);

    let signer = BLSSigner::new(config.private_key.clone());

    let state_client = StateClient::new(&config.execution_api, 8);

    let head = state_client.get_head().await?;

    let mut execution_state = ExecutionState::new(state_client, ChainHead::new(0, head)).await?;

    let mevboost_client = MevBoostClient::new(config.mevboost_url.clone());

    let shutdown_tx = start_server(config, api_events).await?;

    let builder_proxy_config = BuilderProxyConfig::default();

    let (payload_tx, mut payload_rx) = mpsc::channel(1);
    let payload_fetcher = LocalPayloadFetcher::new(payload_tx);

    let _builder_proxy = tokio::spawn(async move {
        if let Err(e) = start_builder_proxy(NoopPayloadFetcher, builder_proxy_config).await {
            tracing::error!("Builder proxy failed: {:?}", e);
        }
    });

    // TODO: parallelize this
    loop {
        tokio::select! {
            Some(event) = api_events_rx.recv() => {
                tracing::info!("Received commitment request: {:?}", event.request);
                let request = event.request;

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
                // TODO: get the validator index from somewhere
                let Ok(message) = ConstraintsMessage::build(0, request.slot, request.clone()) else {
                    tracing::error!("Failed to build constraints message, parsing error");
                    let _ = event
                        .response
                        .send(Err(ApiError::Custom("Internal server error".to_string())));
                    continue;
                };

                let signature = from_bls_signature_to_consensus_signature(signer.sign(&message));
                let signed_constraints: BatchedSignedConstraints =
                    vec![SignedConstraints { message, signature }];

                // TODO: fix retry logic
                while let Err(e) = mevboost_client
                    .submit_constraints(&signed_constraints)
                    .await
                {
                    tracing::error!(error = ?e, "Error submitting constraints, retrying...");
                }
            }
            Some(request) = payload_rx.recv() => {
                tracing::info!("Received payload request: {:?}", request);
                let _response = execution_state.get_block_template(request.slot);
                // TODO: extract payload & bid
                let _ = request.response.send(None);
            }

            else => break,
        }
    }

    tokio::signal::ctrl_c().await?;
    shutdown_tx.send(()).await.ok();

    Ok(())
}
