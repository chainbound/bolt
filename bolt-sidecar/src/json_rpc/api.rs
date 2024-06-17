use std::{num::NonZeroUsize, sync::Arc};

use parking_lot::RwLock;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::info;

use crate::primitives::{CommitmentRequest, InclusionRequest, Slot};

/// Default size of the api request cache (implemented as a LRU).
const DEFAULT_API_REQUEST_CACHE_SIZE: usize = 1000;

/// An error that can occur while processing any API request.
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("failed to parse JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("failed to decode hex string: {0}")]
    DecodeHex(#[from] hex::FromHexError),
    #[error("duplicate: the same request already exists")]
    DuplicateRequest,
    #[error("signature error: {0}")]
    Signature(#[from] alloy_primitives::SignatureError),
    #[error("signature pubkey mismatch. expected: {expected}, got: {got}")]
    SignaturePubkeyMismatch { expected: String, got: String },
    #[error("failed to decode RLP: {0}")]
    Rlp(#[from] alloy_rlp::Error),
    #[error("failed during HTTP call: {0}")]
    Http(#[from] reqwest::Error),
    #[error("downstream error: {0}")]
    Eyre(#[from] eyre::Report),
    #[error("failed while processing API request: {0}")]
    Custom(String),
    #[error("failed to calculate hash tree root for constraints: {0}")]
    MerkleizationError(#[from] ssz_rs::MerkleizationError),
}

/// Alias for the result of an API call that returns a JSON value.
pub type JsonApiResult = Result<Value, ApiError>;

/// The JSON-RPC API trait that defines the methods that can be called.
#[async_trait::async_trait]
pub trait CommitmentsRpc {
    /// Request an inclusion commitment for a given slot.
    async fn request_inclusion_commitment(&self, params: Value) -> JsonApiResult;
}

#[derive(Debug)]
pub struct ApiEvent {
    // TODO: change to commitment request
    pub request: InclusionRequest,
    pub response: oneshot::Sender<JsonApiResult>,
}

/// The struct that implements handlers for all JSON-RPC API methods.
///
/// # Functionality
/// - We keep track of API requests in a local cache in order to avoid
///   accepting duplicate commitments from users.
/// - We also sign each request to irrevocably bind it to this
///   sidecar's validator identity.
pub struct JsonRpcApi {
    /// A cache of commitment requests.
    cache: Arc<RwLock<lru::LruCache<Slot, Vec<CommitmentRequest>>>>,
    /// The event sender for API events.
    event_tx: mpsc::Sender<ApiEvent>,
}

impl JsonRpcApi {
    /// Create a new instance of the JSON-RPC API.
    pub fn new(event_tx: mpsc::Sender<ApiEvent>) -> Arc<Self> {
        let cap = NonZeroUsize::new(DEFAULT_API_REQUEST_CACHE_SIZE).unwrap();

        Arc::new(Self {
            cache: Arc::new(RwLock::new(lru::LruCache::new(cap))),
            event_tx,
        })
    }
}

fn internal_error() -> ApiError {
    ApiError::Custom("internal server error".to_string())
}

#[async_trait::async_trait]
impl CommitmentsRpc for JsonRpcApi {
    async fn request_inclusion_commitment(&self, params: Value) -> JsonApiResult {
        let Some(params) = params.as_array().and_then(|a| a.first()).cloned() else {
            return Err(ApiError::Custom(
                "request params must be an array with a single object".to_string(),
            ));
        };

        let params = serde_json::from_value::<CommitmentRequest>(params)?;
        #[allow(irrefutable_let_patterns)] // TODO: remove this when we have more request types
        let CommitmentRequest::Inclusion(params) = params
        else {
            return Err(ApiError::Custom(
                "request must be an inclusion request".to_string(),
            ));
        };

        info!(?params, "received inclusion commitment request");

        let tx_sender = params.tx.recover_signer()?;

        // validate the user's signature
        let signer_address = params
            .signature
            .recover_address_from_prehash(&params.digest())?;

        // TODO: relax this check to allow for external signers to request commitments
        // about transactions that they did not sign themselves
        if signer_address != tx_sender {
            return Err(ApiError::SignaturePubkeyMismatch {
                expected: tx_sender.to_string(),
                got: signer_address.to_string(),
            });
        }

        {
            // check for duplicate requests and update the cache if necessary
            let mut cache = self.cache.write();
            if let Some(commitments) = cache.get_mut(&params.slot) {
                if commitments
                    .iter()
                    .any(|p| matches!(p, CommitmentRequest::Inclusion(req) if req == &params))
                {
                    return Err(ApiError::DuplicateRequest);
                }

                commitments.push(params.clone().into());
            } else {
                cache.put(params.slot, vec![params.clone().into()]);
            }
        } // Drop the lock

        let (tx, rx) = oneshot::channel();

        // send the request to the event loop
        self.event_tx
            .send(ApiEvent {
                request: params.clone(),
                response: tx,
            })
            .await
            .map_err(|_| internal_error())?;

        let response = rx.await.map_err(|_| internal_error())?;

        Ok(serde_json::to_value("test")?)
    }
}

fn emit_bolt_demo_event<T: Into<String>>(message: T) {
    let msg = message.into();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        client
            .post("http://172.17.0.1:3001/events")
            .header("Content-Type", "application/json")
            .body(
                serde_json::to_string(
                    &serde_json::json!({"message": format!("BOLT-SIDECAR: {}", msg)}),
                )
                .unwrap(),
            )
            .send()
            .await
            .expect("failed to send event to demo server");
    });
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{CommitmentsRpc, JsonApiResult};

    struct MockCommitmentsRpc;

    #[async_trait::async_trait]
    impl CommitmentsRpc for MockCommitmentsRpc {
        async fn request_inclusion_commitment(&self, _params: Value) -> JsonApiResult {
            Ok(Value::Null)
        }
    }

    #[tokio::test]
    async fn test_request_inclusion_commitment() {
        let rpc = MockCommitmentsRpc;
        let params = serde_json::json!([{
            "slot": 1,
            "tx": "0x1234",
            "signature": "0x5678",
        }]);

        let result = rpc.request_inclusion_commitment(params).await;
        assert!(result.is_ok());
    }
}
