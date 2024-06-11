use std::{num::NonZeroUsize, sync::Arc};

use beacon_api_client::mainnet::Client as BeaconApiClient;
use parking_lot::RwLock;
use serde_json::Value;
use thiserror::Error;
use tracing::info;

use super::mevboost::MevBoostClient;
use crate::{
    crypto::{
        bls::{from_bls_signature_to_consensus_signature, BlsSecretKey},
        BLSSigner,
    },
    json_rpc::types::{BatchedSignedConstraints, ConstraintsMessage, SignedConstraints},
    primitives::{CommitmentRequest, Slot},
};

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
}

/// Alias for the result of an API call that returns a JSON value.
pub type JsonApiResult = Result<Value, ApiError>;

/// The JSON-RPC API trait that defines the methods that can be called.
#[async_trait::async_trait]
pub trait CommitmentsRpc {
    /// Request an inclusion commitment for a given slot.
    async fn request_inclusion_commitment(&self, params: Value) -> JsonApiResult;
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
    /// The client for the MEV-Boost sidecar.
    mevboost_client: MevBoostClient,
    /// The client for the beacon node API.
    beacon_api_client: BeaconApiClient,
    /// The signer for this sidecar.
    signer: BLSSigner,
}

impl JsonRpcApi {
    /// Create a new instance of the JSON-RPC API.
    pub fn new(private_key: BlsSecretKey, mevboost_url: String, beacon_url: String) -> Arc<Self> {
        let cap = NonZeroUsize::new(DEFAULT_API_REQUEST_CACHE_SIZE).unwrap();
        let beacon_url = reqwest::Url::parse(&beacon_url).expect("failed to parse beacon node URL");

        Arc::new(Self {
            cache: Arc::new(RwLock::new(lru::LruCache::new(cap))),
            mevboost_client: MevBoostClient::new(mevboost_url),
            beacon_api_client: BeaconApiClient::new(beacon_url),
            signer: BLSSigner::new(private_key),
        })
    }
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

        #[cfg(feature = "demo")]
        let (validator_index, signer) =
            crate::demo::validator_data(&self.beacon_api_client, params.slot).await?;
        #[cfg(not(feature = "demo"))]
        let (validator_index, signer) = (0, &self.signer);

        // parse the request into constraints and sign them with the sidecar signer
        let message =
            ConstraintsMessage::build(validator_index as u64, params.slot, params.clone())?;

        let signature = from_bls_signature_to_consensus_signature(signer.sign(&message));

        let signed_constraints: BatchedSignedConstraints =
            vec![SignedConstraints { message, signature }];

        // TODO: simulate and check if the transaction can be included in the next block
        // self.block_builder.try_append(params.slot, params.tx)

        // TODO: check if there is enough time left in the current slot

        // Web demo: push an event to the demo server to notify the frontend
        emit_bolt_demo_event("commitment request accepted");

        // Forward the constraints to mev-boost's builder API
        self.mevboost_client
            .post_constraints(&signed_constraints)
            .await?;

        Ok(serde_json::to_value(signed_constraints)?)
    }
}

fn emit_bolt_demo_event<T: Into<String>>(message: T) {
    let msg = message.into();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        client
            .post("http://host.docker.internal:3001/events")
            .header("Content-Type", "application/json")
            .body(
                serde_json::to_string(
                    &serde_json::json!({"message": format!("BOLT-SIDECAR: {}", msg)}),
                )
                .unwrap(),
            )
            .send()
            .await
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
