use std::{num::NonZeroUsize, sync::Arc};

use blst::min_pk::SecretKey;
use parking_lot::RwLock;
use serde_json::Value;
use thiserror::Error;
use tracing::info;

use super::types::InclusionRequestParams;
use crate::{bls::Signer, json_rpc::types::InclusionRequestResponse, types::Slot};

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
/// - We also sign each request with a BLS signature to irrevocably bind
///   the request to this sidecar's identity.
pub struct JsonRpcApi {
    /// A cache of commitment requests.
    cache: Arc<RwLock<lru::LruCache<Slot, Vec<InclusionRequestParams>>>>,
    /// The BLS signer for this sidecar.
    bls_signer: Signer,
}

impl JsonRpcApi {
    /// Create a new instance of the JSON-RPC API.
    pub fn new(private_key: SecretKey) -> Self {
        let cap = NonZeroUsize::new(DEFAULT_API_REQUEST_CACHE_SIZE).unwrap();

        Self {
            cache: Arc::new(RwLock::new(lru::LruCache::new(cap))),
            bls_signer: Signer::new(private_key),
        }
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

        let params = serde_json::from_value::<InclusionRequestParams>(params)?;
        info!(?params, "received inclusion commitment request");

        // parse the raw transaction bytes
        hex::decode(params.tx.trim_start_matches("0x")).map_err(ApiError::DecodeHex)?;
        if params.tx.len() % 2 != 0 {
            return Err(ApiError::Custom(
                "tx hash and raw tx must be valid hex strings".to_string(),
            ));
        }

        {
            let mut cache = self.cache.write();
            if let Some(commitments) = cache.get_mut(&params.slot) {
                if commitments.iter().any(|p| p.tx == params.tx) {
                    return Err(ApiError::DuplicateRequest);
                }

                commitments.push(params.clone());
            } else {
                cache.put(params.slot, vec![params.clone()]);
            }
        } // Drop the lock

        // sign the commitment request object
        let signature = hex::encode(self.bls_signer.sign(&params).to_bytes());

        // TODO: simulate and check if the transaction can be included in the next block
        // self.block_builder.try_append(params.slot, params.tx)

        // TODO: check if there is enough time left in the current slot

        // TODO: If valid, broadcast the commitment to all connected relays

        Ok(serde_json::to_value(InclusionRequestResponse {
            request: params,
            signature,
        })?)
    }
}
