use std::{num::NonZeroUsize, sync::Arc};

use alloy_primitives::keccak256;
use blst::min_pk::SecretKey;
use parking_lot::RwLock;
use thiserror::Error;
use tracing::info;

use super::types::{GetPreconfirmationsAtSlotParams, PreconfirmationRequestParams, Slot};
use crate::{bls::Signable, json_rpc::types::PreconfirmationResponse};

/// Default size of the preconfirmation cache (implemented as a LRU).
const DEFAULT_PRECONFIRMATION_CACHE_SIZE: usize = 1000;

#[derive(Error, Debug)]
pub enum PreconfirmationError {
    #[error("failed to parse JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("failed to decode hex string: {0}")]
    DecodeHex(#[from] hex::FromHexError),
    #[error("preconfirmation request already exists")]
    Duplicate,
    #[error("failed while processing preconfirmation: {0}")]
    Custom(String),
}

/// JSON-RPC API for handling preconfirmation requests.
pub(crate) struct JsonRpcApi {
    /// PERF: use a non-locking sharded cache for max performance
    pub(crate) cache: Arc<RwLock<lru::LruCache<Slot, Vec<PreconfirmationRequestParams>>>>,
    pub(crate) private_key: SecretKey,
    pub(crate) relays: Vec<String>,
}

impl JsonRpcApi {
    /// Create a new instance of the JSON-RPC API.
    pub(crate) fn new(private_key: SecretKey, relays: Vec<String>) -> Self {
        let cap = NonZeroUsize::new(DEFAULT_PRECONFIRMATION_CACHE_SIZE).unwrap();

        Self {
            cache: Arc::new(RwLock::new(lru::LruCache::new(cap))),
            private_key,
            relays,
        }
    }
}

/// Trait for handling the preconfirmation JSON-RPC API methods.
#[async_trait::async_trait]
pub(crate) trait PreconfirmationRpc {
    /// Method to request a preconfirmation for a given transaction.
    async fn request_preconfirmation(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, PreconfirmationError>;

    /// Method to get all preconfirmation requests at a given slot.
    async fn get_preconfirmation_requests(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, PreconfirmationError>;
}

#[async_trait::async_trait]
impl PreconfirmationRpc for JsonRpcApi {
    async fn request_preconfirmation(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, PreconfirmationError> {
        let Some(params) = params.as_array().and_then(|a| a.first()).cloned() else {
            return Err(PreconfirmationError::Custom(
                "request params must be an array with a single object".to_string(),
            ));
        };

        let params = serde_json::from_value::<PreconfirmationRequestParams>(params)?;
        info!(?params, "received preconfirmation request");

        let tx_bytes = hex::decode(params.tx.trim_start_matches("0x"))
            .map_err(PreconfirmationError::DecodeHex)?;
        let tx_hash = keccak256(tx_bytes);

        if params.signature.len() != 130 {
            return Err(PreconfirmationError::Custom(
                "signature must be a valid hex string".to_string(),
            ));
        }

        if params.tx.len() % 2 != 0 {
            return Err(PreconfirmationError::Custom(
                "tx must be a valid hex string".to_string(),
            ));
        }

        // sign the preconfirmation request object
        let proposer_signature =
            "0x".to_string() + hex::encode(params.sign_bls(&self.private_key).to_bytes()).as_str();

        {
            let mut cache = self.cache.write();
            if let Some(commitments) = cache.get_mut(&params.slot) {
                if commitments.iter().any(|p| {
                    let phash = keccak256(hex::decode(p.tx.trim_start_matches("0x")).unwrap());
                    phash == tx_hash
                }) {
                    return Err(PreconfirmationError::Duplicate);
                }

                commitments.push(params.clone());
            } else {
                cache.put(params.slot, vec![params.clone()]);
            }
        } // Drop the lock

        // TODO: add simulation step: communicate via a local archive node

        // broadcast the preconfirmation request to all connected relays
        // (in the background to avoid delaying the response)
        self.broadcast_request_to_connected_relays(params.clone());

        Ok(serde_json::to_value(PreconfirmationResponse {
            request: params,
            proposer_signature,
        })?)
    }

    async fn get_preconfirmation_requests(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, PreconfirmationError> {
        let Some(params) = params.as_array().and_then(|a| a.first()).cloned() else {
            return Err(PreconfirmationError::Custom(
                "request params must be an array with a single object".to_string(),
            ));
        };

        let params = serde_json::from_value::<GetPreconfirmationsAtSlotParams>(params)?;
        info!(?params, "received get preconfirmation requests");

        let mut slot_requests = Vec::new();

        {
            if let Some(preconfs) = self.cache.write().get(&params.slot) {
                for preconf in preconfs {
                    slot_requests.push(serde_json::to_value(preconf)?);
                }
            }
        } // Drop the lock

        Ok(serde_json::json!(slot_requests))
    }
}
