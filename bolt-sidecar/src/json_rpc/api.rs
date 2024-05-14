use std::{num::NonZeroUsize, sync::Arc};

use parking_lot::RwLock;
use secp256k1::{
    hashes::{sha256, Hash},
    Message, Secp256k1, SecretKey,
};
use thiserror::Error;
use tracing::info;

use super::types::{PreconfirmationRequestParams, Slot};

/// Default size of the preconfirmation cache (implemented as a LRU).
const DEFAULT_PRECONFIRMATION_CACHE_SIZE: usize = 1000;

#[derive(Error, Debug)]
pub enum PreconfirmationError {
    #[error("failed to parse JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("failed to decode hex string: {0}")]
    DecodeHex(#[from] hex::FromHexError),
    #[error("failed while processing preconfirmation: {0}")]
    Custom(String),
}

pub struct JsonRpcApi {
    cache: Arc<RwLock<lru::LruCache<Slot, Vec<PreconfirmationRequestParams>>>>,
    private_key: Option<SecretKey>,
}

impl JsonRpcApi {
    /// Create a new instance of the JSON-RPC API.
    pub fn new(private_key: Option<SecretKey>) -> Self {
        let cap = NonZeroUsize::new(DEFAULT_PRECONFIRMATION_CACHE_SIZE).unwrap();

        Self {
            cache: Arc::new(RwLock::new(lru::LruCache::new(cap))),
            private_key,
        }
    }
}

#[async_trait::async_trait]
pub trait PreconfirmationRpc {
    async fn request_preconfirmation(
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

        // sanity checks: tx hash and raw tx must be valid hex strings
        hex::decode(params.tx_hash.trim_start_matches("0x"))
            .map_err(PreconfirmationError::DecodeHex)?;
        hex::decode(params.raw_tx.trim_start_matches("0x"))
            .map_err(PreconfirmationError::DecodeHex)?;
        if params.tx_hash.len() != 66 || params.raw_tx.len() % 2 != 0 {
            return Err(PreconfirmationError::Custom(
                "tx hash and raw tx must be valid hex strings".to_string(),
            ));
        }

        // sign the preconfirmation request object
        let signature = if let Some(pk) = self.private_key {
            let secp = Secp256k1::new();
            let digest = sha256::Hash::hash(&params.as_bytes());
            let message = Message::from_digest(digest.to_byte_array());
            Some(secp.sign_ecdsa(&message, &pk).to_string())
        } else {
            None
        };

        {
            let mut cache = self.cache.write();
            if let Some(preconfs) = cache.get_mut(&params.slot) {
                if preconfs.iter().any(|p| p.tx_hash == params.tx_hash) {
                    return Err(PreconfirmationError::Custom(
                        "this preconfirmation request already exists".to_string(),
                    ));
                }

                preconfs.push(params);
            } else {
                cache.put(params.slot, vec![params]);
            }
        } // Drop the lock

        Ok(serde_json::json!({
            "status": "ok",
            "signature": signature,
        }))
    }
}
