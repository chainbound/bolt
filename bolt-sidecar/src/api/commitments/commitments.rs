use alloy::primitives::Signature;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, str::FromStr, sync::Arc};
use tokio::sync::{mpsc, oneshot};

use crate::primitives::{
    commitment::{Commitment, InclusionCommitment},
    CommitmentRequest, InclusionRequest,
};

use super::{
    jsonrpc::{JsonError, JsonPayload, JsonResponse},
    spec::{CommitmentsApi, Error, RejectionError, REQUEST_INCLUSION_METHOD, SIGNATURE_HEADER},
};

struct Event {
    request: CommitmentRequest,
    response: oneshot::Sender<Result<Commitment, RejectionError>>,
}

/// The inner commitments-API handler that implements the [CommitmentsApi] spec.
/// Should be wrapped by a [CommitmentsApiServer] JSON-RPC server to handle requests.
pub struct CommitmentsApiInner {
    /// Event notification channel
    events: mpsc::Sender<Event>,
    /// Optional whitelist of ECDSA public keys
    whitelist: Option<HashSet<PublicKey>>,
}

impl CommitmentsApiInner {
    /// Create a new API server with an optional whitelist of ECDSA public keys.
    pub fn new(events: mpsc::Sender<Event>) -> Self {
        Self {
            events,
            whitelist: None,
        }
    }
}

#[async_trait::async_trait]
impl CommitmentsApi for CommitmentsApiInner {
    async fn request_inclusion(
        &self,
        inclusion_request: InclusionRequest,
    ) -> Result<InclusionCommitment, Error> {
        let (response_tx, response_rx) = oneshot::channel();

        let event = Event {
            request: CommitmentRequest::Inclusion(inclusion_request),
            response: response_tx,
        };

        self.events.send(event).await.unwrap();

        response_rx
            .await
            .map_err(|_| Error::Internal)?
            .map(|c| c.into())
            .map_err(Error::Rejected)
    }
}

/// The outer commitments-API JSON-RPC server that wraps the [CommitmentsApiInner] handler.
pub struct CommitmentsApiServer;

impl CommitmentsApiServer {
    /// Handler function for the root JSON-RPC path.
    #[tracing::instrument(skip(api))]
    async fn handle_rpc(
        State(api): State<Arc<CommitmentsApiInner>>,
        headers: HeaderMap,
        Json(payload): Json<JsonPayload>,
    ) -> Result<JsonResponse, Error> {
        let signature = headers.get(SIGNATURE_HEADER).ok_or({
            tracing::error!("Missing signature");
            Error::NoSignature
        })?;
        tracing::debug!("Received new request");

        match payload.method.as_str() {
            REQUEST_INCLUSION_METHOD => {
                // Parse the inclusion request from the parameters
                let mut inclusion_request: InclusionRequest =
                    serde_json::from_value(payload.params.clone())
                        .map_err(|e| RejectionError::ValidationFailed(e.to_string()))?;

                inclusion_request.signature = Signature::from_str(signature.to_str().unwrap())
                    .map_err(|_| Error::InvalidSignature)?;

                let inclusion_commitment = api.request_inclusion(inclusion_request).await?;

                // Create the JSON-RPC response
                let response = JsonResponse {
                    id: payload.id,
                    result: serde_json::to_value(inclusion_commitment).unwrap(),
                    ..Default::default()
                };

                Ok(response)
            }
            _ => {
                tracing::error!("Unknown method: {}", payload.method);
                Err(Error::UnknownMethod)
            }
        }
    }
}
