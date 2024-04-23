use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

pub type Slot = u64;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PreconfirmationRequestParams {
    slot: Slot,
    tx_hash: String,
    raw_tx: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetPreconfirmationsAtSlotParams {
    slot: Slot,
}

pub struct JsonRpcApi {
    pub cache: Arc<RwLock<lru::LruCache<Slot, Vec<PreconfirmationRequestParams>>>>,
}

#[derive(Error, Debug)]
pub enum PreconfirmationError {
    #[error("failed to parse JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("failed processing preconfirmation: {0}")]
    Custom(String),
}

#[async_trait::async_trait]
pub trait PreconfirmationRpc {
    async fn request_preconfirmation(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, PreconfirmationError>;

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

        Ok(serde_json::json!(true))
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
