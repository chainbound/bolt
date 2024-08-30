use core::fmt;
use std::time::{Duration, Instant};

use alloy::{
    rpc::types::beacon::events::HeadEvent,
    signers::{local::PrivateKeySigner, Signer as SignerECDSA},
};
use beacon_api_client::mainnet::Client as BeaconClient;
use ethereum_consensus::{
    clock::{self, SlotStream, SystemTimeProvider},
    phase0::mainnet::SLOTS_PER_EPOCH,
};
use futures::StreamExt;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    commitments::{
        server::{CommitmentsApiServer, Event as CommitmentEvent},
        spec::Error as CommitmentError,
    },
    crypto::{bls::Signer as BlsSigner, SignableBLS, SignerBLSAsync},
    primitives::{
        CommitmentRequest, ConstraintsMessage, FetchPayloadRequest, LocalPayloadFetcher,
        SignedConstraints,
    },
    start_builder_proxy_server,
    state::{fetcher::StateFetcher, ConsensusState, ExecutionState, HeadTracker, StateClient},
    BuilderProxyConfig, CommitBoostClient, Config, ConstraintsApi, LocalBuilder, MevBoostClient,
};

/// The driver for the sidecar, responsible for managing the main event loop.
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
    /// Stream of slots made from the consensus clock
    slot_stream: SlotStream<SystemTimeProvider>,
}

impl<B: SignerBLSAsync> fmt::Debug for SidecarDriver<StateClient, B, PrivateKeySigner> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SidecarDriver")
            .field("head_tracker", &self.head_tracker)
            .field("execution", &self.execution)
            .field("consensus", &self.consensus)
            .field("constraint_signer", &self.constraint_signer)
            .field("commitment_signer", &self.commitment_signer)
            .field("local_builder", &self.local_builder)
            .field("mevboost_client", &self.mevboost_client)
            .field("api_events_rx", &self.api_events_rx)
            .field("payload_requests_rx", &self.payload_requests_rx)
            .finish()
    }
}

impl SidecarDriver<StateClient, BlsSigner, PrivateKeySigner> {
    /// Create a new sidecar driver with the given [Config] and private key signer.
    pub async fn with_local_signer(cfg: Config) -> eyre::Result<Self> {
        // The default state client simply uses the execution API URL to fetch state updates.
        let state_client = StateClient::new(cfg.execution_api_url.clone());

        // Constraints are signed with a BLS private key
        let constraint_signer = BlsSigner::new(cfg.private_key.clone().unwrap());

        // Commitment responses are signed with a regular Ethereum wallet private key.
        // This is now generated randomly because slashing is not yet implemented.
        let commitment_signer = PrivateKeySigner::random();

        Self::from_components(cfg, constraint_signer, commitment_signer, state_client).await
    }
}

impl SidecarDriver<StateClient, CommitBoostClient, PrivateKeySigner> {
    /// Create a new sidecar driver with the given [Config] and commit-boost signer.
    pub async fn with_commit_boost_signer(cfg: Config) -> eyre::Result<Self> {
        // The default state client simply uses the execution API URL to fetch state updates.
        let state_client = StateClient::new(cfg.execution_api_url.clone());

        // Constraints are signed with a commit-boost signer
        let constraint_signer = CommitBoostClient::new(
            cfg.commit_boost_address.clone().expect("CommitBoost URL must be provided"),
            &cfg.commit_boost_jwt_hex.clone().expect("CommitBoost JWT must be provided"),
        )
        .await?;

        // Commitment responses are signed with a regular Ethereum wallet private key.
        // This is now generated randomly because slashing is not yet implemented.
        let commitment_signer = PrivateKeySigner::random();

        Self::from_components(cfg, constraint_signer, commitment_signer, state_client).await
    }
}

impl<C: StateFetcher, BLS: SignerBLSAsync, ECDSA: SignerECDSA> SidecarDriver<C, BLS, ECDSA> {
    /// Create a new sidecar driver with the given components
    pub async fn from_components(
        cfg: Config,
        constraint_signer: BLS,
        commitment_signer: ECDSA,
        fetcher: C,
    ) -> eyre::Result<Self> {
        let mevboost_client = MevBoostClient::new(cfg.mevboost_url.clone());
        let beacon_client = BeaconClient::new(cfg.beacon_api_url.clone());
        let execution = ExecutionState::new(fetcher, cfg.limits).await?;

        let genesis_time = beacon_client.get_genesis_details().await?.genesis_time;
        let slot_stream =
            clock::from_system_time(genesis_time, cfg.chain.slot_time(), SLOTS_PER_EPOCH)
                .into_stream();

        let local_builder = LocalBuilder::new(&cfg, beacon_client.clone(), genesis_time);
        let head_tracker = HeadTracker::start(beacon_client.clone());

        let consensus = ConsensusState::new(
            beacon_client,
            cfg.validator_indexes.clone(),
            cfg.chain.commitment_deadline(),
        );

        let (payload_requests_tx, payload_requests_rx) = mpsc::channel(16);
        let builder_proxy_cfg = BuilderProxyConfig {
            mevboost_url: cfg.mevboost_url.clone(),
            server_port: cfg.mevboost_proxy_port,
        };

        // start the builder api proxy server
        tokio::spawn(async move {
            let payload_fetcher = LocalPayloadFetcher::new(payload_requests_tx);
            if let Err(err) = start_builder_proxy_server(payload_fetcher, builder_proxy_cfg).await {
                error!(?err, "Builder API proxy server failed");
            }
        });

        // start the commitments api server
        let api_addr = format!("0.0.0.0:{}", cfg.rpc_port);
        let (api_events_tx, api_events_rx) = mpsc::channel(1024);
        CommitmentsApiServer::new(api_addr).run(api_events_tx).await;

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
            slot_stream,
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
                    self.handle_commitment_deadline(slot).await;
                }
                Some(payload_request) = self.payload_requests_rx.recv() => {
                    self.handle_fetch_payload_request(payload_request);
                }
                Some(slot) = self.slot_stream.next() => {
                    if let Err(e) = self.consensus.update_slot(slot).await {
                        error!(err = ?e, "Failed to update consensus state slot");
                    }
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
        let signed_constraints = match self.constraint_signer.sign(&message.digest()).await {
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

    /// Handle a new head event, updating the execution state.
    async fn handle_new_head_event(&mut self, head_event: HeadEvent) {
        let slot = head_event.slot;
        info!(slot, "Received new head event");

        // We use None to signal that we want to fetch the latest EL head
        if let Err(e) = self.execution.update_head(None, slot).await {
            error!(err = ?e, "Failed to update execution state head");
        }
    }

    /// Handle a commitment deadline event, submitting constraints to the MEV-Boost service
    /// and starting to build a local payload for the given target slot.
    async fn handle_commitment_deadline(&mut self, slot: u64) {
        debug!(slot, "Commitment deadline reached, building local block");

        let Some(template) = self.execution.get_block_template(slot) else {
            warn!("No block template found for slot {slot} when requested");
            return;
        };

        if let Err(e) = self.local_builder.build_new_local_payload(slot, template).await {
            error!(err = ?e, "Error while building local payload at deadline for slot {slot}");
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
