use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use alloy::rpc::types::beacon::events::HeadEvent;
use eyre::{eyre, Result};
use futures::{Future, StreamExt};
use tokio::sync::mpsc;

use crate::{
    crypto::{SignableBLS, SignerBLS},
    json_rpc::api::{ApiError, ApiEvent},
    primitives::{CommitmentRequest, ConstraintsMessage, FetchPayloadRequest, SignedConstraints},
    state::{ConsensusState, ExecutionState, HeadTracker, StateFetcher},
    ConstraintsApi, LocalBuilder, MevBoostClient,
};

/// The main driver for the sidecar, managing the event loop and coordinating
/// the various components of the system.
#[derive(Debug)]
pub struct SidecarDriver<C, S> {
    head_tracker: HeadTracker,
    execution_state: ExecutionState<C>,
    consensus_state: ConsensusState,
    signer: S,
    local_builder: LocalBuilder,
    mevboost_client: MevBoostClient,
    shutdown_rx: mpsc::Receiver<()>,
    api_events_rx: mpsc::Receiver<ApiEvent>,
    payload_requests_rx: mpsc::Receiver<FetchPayloadRequest>,
}

/// Helper macro to simplify the handling of `Poll::Ready` results in the driver loop.
#[macro_export]
macro_rules! try_ready {
    ($e:expr) => {
        match $e {
            Poll::Ready(Some(t)) => Some(t),
            Poll::Ready(None) => return Poll::Ready(Err(eyre!("driver: channel closed"))),
            // If the future is not ready, pass-through to the next event
            Poll::Pending => None,
        }
    };
}

impl<C: StateFetcher + Unpin, S: SignerBLS + Unpin> Future for SidecarDriver<C, S> {
    type Output = Result<()>;

    /// Main event loop for the sidecar driver, polling all the internal
    /// components and handling the various events.
    ///
    /// This poll implementation does not prioritize any channel, and tries to
    /// make progress on all of them in each iteration.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let mut progress = false;

            if let Some(api_event) = try_ready!(this.api_events_rx.poll_recv(cx)) {
                this.handle_incoming_api_event(api_event);
                progress = true;
            }

            if let Some(head_event) = try_ready!(this.head_tracker.poll_next_unpin(cx)) {
                this.handle_new_head_event(head_event);
                progress = true;
            }

            if let Some(slot) = try_ready!(this.consensus_state.commitment_deadline.poll_wait(cx)) {
                this.handle_commitment_deadline(slot);
                progress = true;
            }

            if let Some(req) = try_ready!(this.payload_requests_rx.poll_recv(cx)) {
                this.handle_fetch_payload_request(req);
                progress = true;
            }

            if this.shutdown_rx.poll_recv(cx).is_ready() {
                tracing::warn!("Received shutdown signal, shutting down...");
                return Poll::Ready(Ok(()));
            }

            // If we made any progress during the loop, continue processing, otherwise
            // return pending to wait for the next event.
            if !progress {
                return Poll::Pending;
            }
        }
    }
}

impl<C: StateFetcher + Unpin, S: SignerBLS + Unpin> SidecarDriver<C, S> {
    fn handle_incoming_api_event(&mut self, api_event: ApiEvent) {
        tracing::info!("Received commitment request: {:?}", api_event.request);
        let start = Instant::now();

        let validator_index = match self.consensus_state.validate_request(&api_event.request) {
            Ok(index) => index,
            Err(e) => {
                tracing::error!("Failed to validate request: {:?}", e);
                let _ = api_event.response_tx.send(Err(ApiError::Consensus(e)));
                return;
            }
        };

        if let Err(e) = self
            .execution_state
            .validate_commitment_request(&api_event.request)
            .await
        {
            tracing::error!("Failed to commit request: {:?}", e);
            let _ = api_event.response_tx.send(Err(ApiError::Validation(e)));
            return;
        }

        // TODO: match when we have more request types
        let CommitmentRequest::Inclusion(request) = api_event.request;
        let target_slot = request.slot;

        tracing::info!(
            elapsed = ?start.elapsed(),
            tx_hash = %request.tx.hash(),
            "Validation against execution state passed"
        );

        // parse the request into constraints and sign them with the sidecar signer
        let message = ConstraintsMessage::build(validator_index, request);
        let signature = match self.signer.sign(&message.digest()) {
            Ok(sig) => sig.to_string(),
            Err(e) => {
                let _ = api_event.response_tx.send(Err(ApiError::Eyre(e)));
                return;
            }
        };

        let signed_constraints = SignedConstraints { message, signature };

        self.execution_state
            .add_constraint(target_slot, signed_constraints.clone());

        let res = serde_json::to_value(signed_constraints).map_err(Into::into);
        let _ = api_event.response_tx.send(res);
    }

    fn handle_new_head_event(&mut self, head_event: HeadEvent) {
        let slot = head_event.slot;
        tracing::info!(slot, "Received new head event");

        // We use None to signal that we want to fetch the latest EL head
        if let Err(e) = self.execution_state.update_head(None, slot).await {
            tracing::error!(err = ?e, "Failed to update execution state head");
        }

        if let Err(e) = self.consensus_state.update_head(slot).await {
            tracing::error!(err = ?e, "Failed to update consensus state head");
        }
    }

    fn handle_commitment_deadline(&mut self, slot: u64) {
        tracing::debug!(
            slot,
            "Commitment deadline reached, starting to build local block"
        );

        let Some(template) = self.execution_state.get_block_template(slot) else {
            tracing::warn!("No block template found for slot {slot} when requested");
            return;
        };

        // TODO: fix retry logic, and move this to separate task in the mevboost client itself
        let constraints = template.signed_constraints_list.clone();
        let mevboost = self.mevboost_client.clone();
        tokio::spawn(async move {
            let max_retries = 5;
            let mut i = 0;
            while let Err(e) = mevboost.submit_constraints(&constraints).await {
                tracing::error!(err = ?e, "Error submitting constraints to mev-boost, retrying...");
                tokio::time::sleep(Duration::from_millis(100)).await;
                i += 1;
                if i >= max_retries {
                    tracing::error!("Max retries reached while submitting to MEV-Boost");
                    break;
                }
            }
        });
    }

    fn handle_fetch_payload_request(&mut self, request: FetchPayloadRequest) {
        tracing::info!(slot = request.slot, "Received local payload request");

        let Some(payload_and_bid) = self.local_builder.get_cached_payload() else {
            tracing::warn!(slot = request.slot, "No local payload found");
            let _ = request.response_tx.send(None);
            return;
        };

        if let Err(e) = request.response_tx.send(Some(payload_and_bid)) {
            tracing::error!(err = ?e, "Failed to send payload and bid in response channel");
        } else {
            tracing::debug!("Sent payload and bid to response channel");
        }
    }
}
