use alloy::primitives::{Address, Signature};
use axum::{extract::State, http::HeaderMap, routing::post, Json};
use axum_extra::extract::WithRejection;
use std::{
    collections::HashSet,
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
    sync::Arc,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};

use crate::primitives::{
    commitment::{Commitment, InclusionCommitment},
    CommitmentRequest, InclusionRequest,
};

use super::{
    jsonrpc::{JsonPayload, JsonResponse},
    spec::{CommitmentsApi, Error, RejectionError, REQUEST_INCLUSION_METHOD, SIGNATURE_HEADER},
};

/// Event type emitted by the commitments API.
pub struct Event {
    request: CommitmentRequest,
    response: oneshot::Sender<Result<Commitment, RejectionError>>,
}

/// The inner commitments-API handler that implements the [CommitmentsApi] spec.
/// Should be wrapped by a [CommitmentsApiServer] JSON-RPC server to handle requests.
pub struct CommitmentsApiInner {
    /// Event notification channel
    events: mpsc::Sender<Event>,
    /// Optional whitelist of ECDSA public keys
    whitelist: Option<HashSet<Address>>,
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
pub struct CommitmentsApiServer {
    /// The address to bind the server to. This will be updated
    /// with the actual address after the server is started.
    addr: SocketAddr,
}

impl CommitmentsApiServer {
    pub fn new<A: ToSocketAddrs>(addr: A) -> Self {
        Self {
            addr: addr.to_socket_addrs().unwrap().next().unwrap(),
        }
    }

    /// Runs the JSON-RPC server in the background, sending events to the provided channel.
    pub async fn run(&mut self, events_tx: mpsc::Sender<Event>) -> eyre::Result<()> {
        let api = Arc::new(CommitmentsApiInner::new(events_tx));

        let router = axum::Router::new()
            .route("/", post(Self::handle_rpc))
            .with_state(api);

        let listener = TcpListener::bind(self.addr).await?;
        let addr = listener.local_addr()?;

        self.addr = addr;

        tracing::info!("Commitments RPC server bound to {addr}");

        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("Server error: {:?}", e);
            }
        });

        Ok(())
    }

    /// Returns the local addr the server is listening on (or configured with).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Handler function for the root JSON-RPC path.
    #[tracing::instrument(skip_all)]
    async fn handle_rpc(
        headers: HeaderMap,
        State(api): State<Arc<CommitmentsApiInner>>,
        WithRejection(Json(payload), _): WithRejection<Json<JsonPayload>, Error>,
    ) -> Result<Json<JsonResponse>, Error> {
        tracing::debug!(method = payload.method, "Received new request");

        let signature = signature_from_headers(&headers)?;

        match payload.method.as_str() {
            REQUEST_INCLUSION_METHOD => {
                // Parse the inclusion request from the parameters
                let mut inclusion_request: InclusionRequest =
                    serde_json::from_value(payload.params.clone())
                        .map_err(|e| RejectionError::ValidationFailed(e.to_string()))?;

                // Set the signature here for later processing
                inclusion_request.signature = Some(signature);

                let digest = inclusion_request.digest();
                let address = signature.recover_address_from_prehash(&digest)?;
                tracing::debug!(?address, "Recovered public key and associated address");

                let inclusion_commitment = api.request_inclusion(inclusion_request).await?;

                // Create the JSON-RPC response
                let response = JsonResponse {
                    id: payload.id,
                    result: serde_json::to_value(inclusion_commitment).unwrap(),
                    ..Default::default()
                };

                Ok(Json(response))
            }
            _ => {
                tracing::error!("Unknown method: {}", payload.method);
                Err(Error::UnknownMethod)
            }
        }
    }
}

/// Extracts the signature ([SIGNATURE_HEADER]) from the HTTP headers.
fn signature_from_headers(headers: &HeaderMap) -> Result<Signature, Error> {
    let signature = headers.get(SIGNATURE_HEADER).ok_or({
        tracing::error!("Missing signature");
        Error::NoSignature
    })?;

    // Remove the "0x" prefix
    let signature = signature.to_str().map_err(|_| Error::InvalidSignature)?;

    Signature::from_str(signature).map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use alloy::primitives::TxHash;
    use alloy::signers::{local::PrivateKeySigner, Signer};

    use crate::primitives::commitment::ECDSASignatureExt;

    use super::*;

    #[tokio::test]
    async fn test_signature_from_headers() {
        let mut headers = HeaderMap::new();
        let hash = TxHash::random();
        let signer = PrivateKeySigner::random();

        let expected_sig = signer.sign_hash(&hash).await.unwrap();
        headers.insert(SIGNATURE_HEADER, expected_sig.to_hex().parse().unwrap());

        let signature = signature_from_headers(&headers).unwrap();
        assert_eq!(signature, expected_sig);
    }

    #[tokio::test]
    async fn test_simple_request() {
        let _ = tracing_subscriber::fmt::try_init();

        let mut server = CommitmentsApiServer::new("0.0.0.0:0");

        let (events_tx, mut events_rx) = mpsc::channel(1);

        server.run(events_tx).await.unwrap();

        let addr = server.local_addr();

        tracing::info!("Test server running on {addr}");

        events_rx.recv().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
