/// The commitments-API request handlers.
mod handlers;

/// The commitments-API headers and constants.
mod headers;

/// The commitments-API middleware.
mod middleware;

use middleware::track_server_metrics;

use std::{
    fmt,
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::Arc,
};

use axum::{
    routing::{get, post},
    Router,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info};

use crate::{
    config::limits::LimitsOpts,
    primitives::{
        commitment::{InclusionCommitment, SignedCommitment},
        CommitmentRequest, InclusionRequest,
    },
};

use super::spec::{CommitmentError, CommitmentsApi, MAX_REQUEST_TIMEOUT};

/// Event type emitted by the commitments API.
#[derive(Debug)]
pub struct CommitmentEvent {
    /// The request to process.
    pub request: CommitmentRequest,
    /// The response channel.
    pub response: oneshot::Sender<Result<SignedCommitment, CommitmentError>>,
}

/// The inner commitments-API handler that implements the [CommitmentsApi] spec.
/// Should be wrapped by a [CommitmentsApiServer] JSON-RPC server to handle requests.
#[derive(Debug)]
pub struct CommitmentsApiInner {
    /// Event notification channel
    events: mpsc::Sender<CommitmentEvent>,
    /// The sidecar's operating limits that should be exposed in a metadata endpoint
    limits: LimitsOpts,
}

impl CommitmentsApiInner {
    /// Creates a new instance of the commitments API handler.
    pub fn new(events: mpsc::Sender<CommitmentEvent>, limits: LimitsOpts) -> Self {
        Self { events, limits }
    }

    /// Returns the operating limits for the sidecar.
    pub fn limits(&self) -> LimitsOpts {
        self.limits
    }
}

#[async_trait::async_trait]
impl CommitmentsApi for CommitmentsApiInner {
    async fn request_inclusion(
        &self,
        inclusion_request: InclusionRequest,
    ) -> Result<InclusionCommitment, CommitmentError> {
        let (response_tx, response_rx) = oneshot::channel();

        let event = CommitmentEvent {
            request: CommitmentRequest::Inclusion(inclusion_request),
            response: response_tx,
        };

        self.events.send(event).await.unwrap();

        response_rx.await.map_err(|_| CommitmentError::Internal)?.map(|c| c.into())
    }
}

/// The outer commitments-API JSON-RPC server that wraps the [CommitmentsApiInner] handler.
pub struct CommitmentsApiServer {
    /// The address to bind the server to. This will be updated
    /// with the actual address after the server is started.
    addr: SocketAddr,
    /// The shutdown signal.
    signal: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl fmt::Debug for CommitmentsApiServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitmentsApiServer").field("addr", &self.addr).finish()
    }
}

impl CommitmentsApiServer {
    /// Creates the server with the given address and default shutdown signal (CTRL+C).
    pub fn new<A: ToSocketAddrs>(addr: A) -> Self {
        Self {
            addr: addr.to_socket_addrs().unwrap().next().unwrap(),
            signal: Some(Box::pin(async {
                let _ = tokio::signal::ctrl_c().await;
            })),
        }
    }

    /// Creates the server with the given address and shutdown signal.
    pub fn with_shutdown<A, S>(self, addr: A, signal: S) -> Self
    where
        A: ToSocketAddrs,
        S: Future<Output = ()> + Send + 'static,
    {
        Self {
            addr: addr.to_socket_addrs().unwrap().next().unwrap(),
            signal: Some(Box::pin(signal)),
        }
    }

    /// Runs the JSON-RPC server, sending events to the provided channel.
    pub async fn run(&mut self, events_tx: mpsc::Sender<CommitmentEvent>, limits: LimitsOpts) {
        let api = Arc::new(CommitmentsApiInner::new(events_tx, limits));

        let router = make_router(api);

        let listener = match TcpListener::bind(self.addr).await {
            Ok(listener) => listener,
            Err(err) => {
                error!(?err, "Failed to bind Commitments API server");
                panic!("Failed to bind Commitments API server");
            }
        };

        let addr = listener.local_addr().expect("Failed to get local address");
        self.addr = addr;

        info!("Commitments RPC server bound to {addr}");

        let signal = self.signal.take().expect("Signal not set");

        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, router).with_graceful_shutdown(signal).await {
                error!(?err, "Commitments API Server error");
            }
        });
    }

    /// Returns the local addr the server is listening on (or configured with).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Creates a new [Router]
///
/// NOTE: Keeping the router separate from the server start method allows
/// for easier integration testing through the [`tower::Service`] interface.
#[inline]
fn make_router(state: Arc<CommitmentsApiInner>) -> Router {
    Router::new()
        .route("/", post(handlers::rpc_entrypoint))
        .route("/status", get(handlers::status))
        .fallback(handlers::not_found)
        .layer(TimeoutLayer::new(MAX_REQUEST_TIMEOUT))
        .route_layer(axum::middleware::from_fn(track_server_metrics))
        .with_state(state)
}

#[cfg(test)]
mod test {
    use crate::{
        api::commitments::spec::{MetadataResponse, SIGNATURE_HEADER},
        common::BOLT_SIDECAR_VERSION,
        primitives::jsonrpc::JsonRpcError,
    };
    use alloy::signers::{k256::SecretKey, local::PrivateKeySigner};
    use serde_json::json;

    use crate::{
        primitives::{jsonrpc::JsonRpcResponse, signature::ECDSASignatureExt},
        test_util::{create_signed_inclusion_request, default_test_transaction},
    };

    use super::*;

    #[tokio::test]
    async fn test_request_unauthorized() {
        let _ = tracing_subscriber::fmt::try_init();

        let mut server = CommitmentsApiServer::new("0.0.0.0:0");

        let (events_tx, _) = mpsc::channel(1);

        server.run(events_tx, LimitsOpts::default()).await;
        let addr = server.local_addr();

        let sk = SecretKey::random(&mut rand::thread_rng());
        let signer = PrivateKeySigner::from(sk.clone());
        let tx = default_test_transaction(signer.address(), None);
        let req = create_signed_inclusion_request(&[tx], &sk.to_bytes(), 12).await.unwrap();

        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "bolt_requestInclusion",
            "params": [req]
        });

        let url = format!("http://{addr}");

        let client = reqwest::Client::new();
        // client.post(url).header("content-type", "application/json").body(payload)

        let response = client
            .post(url)
            .json(&payload)
            .send()
            .await
            .unwrap()
            .json::<JsonRpcResponse>()
            .await
            .unwrap();

        // Assert unauthorized because of missing signature
        let expected_error: JsonRpcError = CommitmentError::NoSignature.into();
        assert_eq!(response.into_error().unwrap().code(), expected_error.code);
    }

    #[tokio::test]
    async fn test_request_success() {
        let _ = tracing_subscriber::fmt::try_init();

        let mut server = CommitmentsApiServer::new("0.0.0.0:0");

        let (events_tx, mut events) = mpsc::channel(1);

        server.run(events_tx, LimitsOpts::default()).await;
        let addr = server.local_addr();

        let sk = SecretKey::random(&mut rand::thread_rng());
        let signer = PrivateKeySigner::from(sk.clone());
        let tx = default_test_transaction(signer.address(), None);
        let req = create_signed_inclusion_request(&[tx], &sk.to_bytes(), 12).await.unwrap();

        let sig = req.signature.unwrap().to_hex();

        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "bolt_requestInclusion",
            "params": [req]
        });

        let url = format!("http://{addr}");

        let client = reqwest::Client::new();
        // client.post(url).header("content-type", "application/json").body(payload)

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let response = client
                .post(url)
                .header(SIGNATURE_HEADER, format!("{}:{}", signer.address(), sig))
                .json(&payload)
                .send()
                .await
                .unwrap();

            let json = response.json::<JsonRpcResponse>().await.unwrap();

            // Assert unauthorized because of missing signature
            assert!(json.into_success().is_some());

            let _ = tx.send(());
        });

        let CommitmentEvent { request, response } = events.recv().await.unwrap();

        let commitment_signer = PrivateKeySigner::random();

        let commitment = request.commit_and_sign(&commitment_signer).await.unwrap();

        response.send(Ok(commitment)).unwrap();

        rx.await.unwrap();
    }

    #[tokio::test]
    async fn test_request_metadata() {
        let _ = tracing_subscriber::fmt::try_init();
        let mut server = CommitmentsApiServer::new("0.0.0.0:0");
        let (events_tx, _) = mpsc::channel(1);

        let expected_limits = LimitsOpts::default();
        server.run(events_tx, expected_limits).await;
        let addr = server.local_addr();

        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "bolt_metadata",
            "params": []
        });

        let url = format!("http://{addr}");
        let client = reqwest::Client::new();
        let response = client
            .post(url)
            .json(&payload)
            .send()
            .await
            .unwrap()
            .json::<JsonRpcResponse>()
            .await
            .unwrap();

        let metadata: MetadataResponse =
            serde_json::from_value(response.into_success().unwrap().result).unwrap();

        assert_eq!(
            metadata.limits.max_committed_gas_per_slot,
            expected_limits.max_committed_gas_per_slot
        );
        assert_eq!(metadata.limits.min_inclusion_profit, expected_limits.min_inclusion_profit);
        assert_eq!(
            metadata.limits.max_account_states_size,
            expected_limits.max_account_states_size
        );
        assert_eq!(metadata.version, BOLT_SIDECAR_VERSION.to_string());
    }
}
