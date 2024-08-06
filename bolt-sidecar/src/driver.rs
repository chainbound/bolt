use std::time::{Duration, Instant};

use alloy::{
    rpc::types::beacon::events::HeadEvent,
    signers::{local::PrivateKeySigner, Signer as SignerECDSA},
};
use beacon_api_client::mainnet::Client as BeaconClient;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    commitments::{
        server::{CommitmentsApiServer, Event as CommitmentEvent},
        spec::Error as CommitmentError,
    },
    crypto::{bls::Signer as BlsSigner, SignableBLS, SignerBLS},
    primitives::{
        CommitmentRequest, ConstraintsMessage, FetchPayloadRequest, LocalPayloadFetcher,
        SignedConstraints,
    },
    start_builder_proxy_server,
    state::{fetcher::StateFetcher, ConsensusState, ExecutionState, HeadTracker, StateClient},
    BuilderProxyConfig, Config, ConstraintsApi, LocalBuilder, MevBoostClient,
};

/// The driver for the sidecar, responsible for managing the main event loop.
#[derive(Debug)]
pub struct SidecarDriver<C, BLS, ECDSA> {
    head_tracker: HeadTracker,
    execution: ExecutionState<C>,
    consensus: ConsensusState,
    constraint_signer: BLS,
    commitment_signer: ECDSA,
    local_builder: LocalBuilder,
    mevboost_client: MevBoostClient,
    api_events_rx: mpsc::Receiver<CommitmentEvent>,
    payload_requests_rx: mpsc::Receiver<FetchPayloadRequest>,
}

impl SidecarDriver<StateClient, BlsSigner, PrivateKeySigner> {
    /// Create a new sidecar driver with the given [Config] and default components.
    pub async fn new(cfg: Config) -> eyre::Result<Self> {
        // The default state client simply uses the execution API URL to fetch state updates.
        let state_client = StateClient::new(cfg.execution_api_url.clone());

        // Constraints are signed with a BLS private key, for now this is provided
        // via CLI argument but this is expected to change soon.
        let constraint_signer = BlsSigner::new(cfg.private_key.clone().unwrap());

        // Commitment responses are signed with a regular Ethereum wallet private key.
        // This is now generated randomly because slashing is not yet implemented.
        let commitment_signer = PrivateKeySigner::random();

        Self::from_components(cfg, constraint_signer, commitment_signer, state_client).await
    }
}

impl<C: StateFetcher, BLS: SignerBLS, ECDSA: SignerECDSA> SidecarDriver<C, BLS, ECDSA> {
    /// Create a new sidecar driver with the given components
    pub async fn from_components(
        cfg: Config,
        constraint_signer: BLS,
        commitment_signer: ECDSA,
        fetcher: C,
    ) -> eyre::Result<Self> {
        let mevboost_client = MevBoostClient::new(cfg.mevboost_url.clone());
        let execution = ExecutionState::new(fetcher, cfg.limits).await?;
        let local_builder = LocalBuilder::new(&cfg);

        let beacon_client = BeaconClient::new(cfg.beacon_api_url.clone());

        // start the commitments api server
        let api_addr = format!("0.0.0.0:{}", cfg.rpc_port);
        let (api_events_tx, api_events_rx) = mpsc::channel(1024);
        CommitmentsApiServer::new(api_addr).run(api_events_tx).await;

        let consensus = ConsensusState::new(
            beacon_client.clone(),
            cfg.validator_indexes.clone(),
            cfg.chain.commitment_deadline(),
        );

        // TODO: this can be replaced with ethereum_consensus::clock::from_system_time()
        // but using beacon node events is easier to work on a custom devnet for now
        // (as we don't need to specify genesis time and slot duration)
        let head_tracker = HeadTracker::start(beacon_client);

        let builder_proxy_cfg = BuilderProxyConfig {
            mevboost_url: cfg.mevboost_url.clone(),
            server_port: cfg.mevboost_proxy_port,
        };

        let (payload_requests_tx, payload_requests_rx) = mpsc::channel(16);

        // start the builder api proxy server
        tokio::spawn(async move {
            let payload_fetcher = LocalPayloadFetcher::new(payload_requests_tx);
            if let Err(err) = start_builder_proxy_server(payload_fetcher, builder_proxy_cfg).await {
                error!(?err, "Builder API proxy server failed");
            }
        });

        Ok(SidecarDriver {
            head_tracker,
            execution,
            consensus,
            constraint_signer,
            commitment_signer,
            local_builder,
            mevboost_client,
            api_events_rx,
            payload_requests_rx,
        })
    }

    /// Run the main event loop endlessly for the sidecar driver.
    ///
    /// Any errors encountered are contained to the specific `handler` in which
    /// they occurred, and the driver will continue to run as long as possible.
    pub async fn run_forever(mut self) -> ! {
        loop {
            tokio::select! {
                Some(api_event) = self.api_events_rx.recv() => {
                    self.handle_incoming_api_event(api_event).await;
                }
                Ok(head_event) = self.head_tracker.next_head() => {
                    self.handle_new_head_event(head_event).await;
                }
                Some(slot) = self.consensus.commitment_deadline.wait() => {
                    self.handle_commitment_deadline(slot);
                }
                Some(payload_request) = self.payload_requests_rx.recv() => {
                    self.handle_fetch_payload_request(payload_request);
                }
            }
        }
    }

    /// Handle an incoming API event, validating the request and responding with a commitment.
    async fn handle_incoming_api_event(&mut self, event: CommitmentEvent) {
        let CommitmentEvent { mut request, response } = event;
        info!("Received new commitment request: {:?}", request);
        let start = Instant::now();

        let validator_index = match self.consensus.validate_request(&request) {
            Ok(index) => index,
            Err(err) => {
                error!(?err, "Consensus: failed to validate request");
                let _ = response.send(Err(CommitmentError::Consensus(err)));
                return;
            }
        };

        if let Err(err) = self.execution.validate_request(&mut request).await {
            error!(?err, "Execution: failed to commit request");
            let _ = response.send(Err(CommitmentError::Validation(err)));
            return;
        }

        // TODO: match when we have more request types
        let CommitmentRequest::Inclusion(inclusion_request) = request.clone();
        let target_slot = inclusion_request.slot;

        info!(
            target_slot,
            elapsed = ?start.elapsed(),
            "Validation against execution state passed"
        );

        // parse the request into constraints and sign them
        let slot = inclusion_request.slot;
        let message = ConstraintsMessage::build(validator_index, inclusion_request);
        let signed_constraints = match self.constraint_signer.sign(&message.digest()) {
            Ok(signature) => SignedConstraints { message, signature },
            Err(err) => {
                error!(?err, "Failed to sign constraints");
                let _ = response.send(Err(CommitmentError::Internal));
                return;
            }
        };

        self.execution.add_constraint(slot, signed_constraints);

        // Create a commitment by signing the request
        match request.commit_and_sign(&self.commitment_signer).await {
            Ok(commitment) => response.send(Ok(commitment)).ok(),
            Err(err) => {
                error!(?err, "Failed to sign commitment");
                response.send(Err(CommitmentError::Internal)).ok()
            }
        };
    }

    /// Handle a new head event, updating the execution and consensus state.
    async fn handle_new_head_event(&mut self, head_event: HeadEvent) {
        let slot = head_event.slot;
        info!(slot, "Received new head event");

        // We use None to signal that we want to fetch the latest EL head
        if let Err(e) = self.execution.update_head(None, slot).await {
            error!(err = ?e, "Failed to update execution state head");
        }

        if let Err(e) = self.consensus.update_head(slot).await {
            error!(err = ?e, "Failed to update consensus state head");
        }
    }

    /// Handle a commitment deadline event, submitting constraints to the MEV-Boost service.
    fn handle_commitment_deadline(&mut self, slot: u64) {
        debug!(slot, "Commitment deadline reached, building local block");

        let Some(template) = self.execution.get_block_template(slot) else {
            warn!("No block template found for slot {slot} when requested");
            return;
        };

        // TODO: fix retry logic, and move this to separate task in the mevboost client itself
        let constraints = template.signed_constraints_list.clone();
        let mevboost = self.mevboost_client.clone();
        tokio::spawn(async move {
            let max_retries = 5;
            let mut i = 0;
            while let Err(e) = mevboost.submit_constraints(&constraints).await {
                error!(err = ?e, "Error submitting constraints to mev-boost, retrying...");
                tokio::time::sleep(Duration::from_millis(100)).await;
                i += 1;
                if i >= max_retries {
                    error!("Max retries reached while submitting to MEV-Boost");
                    break;
                }
            }
        });
    }

    /// Handle a fetch payload request, responding with the local payload if available.
    fn handle_fetch_payload_request(&mut self, request: FetchPayloadRequest) {
        info!(slot = request.slot, "Received local payload request");

        let Some(payload_and_bid) = self.local_builder.get_cached_payload() else {
            warn!(slot = request.slot, "No local payload found");
            let _ = request.response_tx.send(None);
            return;
        };

        if let Err(e) = request.response_tx.send(Some(payload_and_bid)) {
            error!(err = ?e, "Failed to send payload and bid in response channel");
        }
    }
}
