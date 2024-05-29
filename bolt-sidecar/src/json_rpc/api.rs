use std::{num::NonZeroUsize, str::FromStr, sync::Arc};

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::Signature;
use parking_lot::RwLock;
use secp256k1::SecretKey;
use serde_json::Value;
use thiserror::Error;
use tracing::info;

use super::types::InclusionRequestParams;
use crate::{
    crypto::{SignableECDSA, Signer},
    json_rpc::types::InclusionRequestResponse,
    types::Slot,
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
    #[error("failed to decode RLP: {0}")]
    Rlp(#[from] alloy_rlp::Error),
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
    /// The signer for this sidecar.
    signer: Signer,
}

impl JsonRpcApi {
    /// Create a new instance of the JSON-RPC API.
    pub fn new(private_key: SecretKey) -> Self {
        let cap = NonZeroUsize::new(DEFAULT_API_REQUEST_CACHE_SIZE).unwrap();

        Self {
            cache: Arc::new(RwLock::new(lru::LruCache::new(cap))),
            signer: Signer::new(private_key),
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
        let hex_decoded_tx = hex::decode(params.message.tx.trim_start_matches("0x"))?;
        let transaction = TxEnvelope::decode_2718(&mut hex_decoded_tx.as_slice())?;
        let tx_sender = transaction.recover_signer()?;

        // validate the user's signature
        let user_sig = Signature::from_str(params.signature.trim_start_matches("0x"))?;
        let signer_address = user_sig.recover_address_from_msg(params.message.digest().as_ref())?;

        // TODO: relax this check to allow for external signers to request commitments
        // about transactions that they did not sign themselves
        if signer_address != tx_sender {
            return Err(ApiError::Custom(
                "commitment signature does not match the transaction sender".to_string(),
            ));
        }

        {
            let mut cache = self.cache.write();
            if let Some(commitments) = cache.get_mut(&params.message.slot) {
                if commitments.iter().any(|p| p == &params) {
                    return Err(ApiError::DuplicateRequest);
                }

                commitments.push(params.clone());
            } else {
                cache.put(params.message.slot, vec![params.clone()]);
            }
        } // Drop the lock

        // sign the commitment request object
        let sidecar_signature = self.signer.sign_ecdsa(&params).to_string();

        // TODO: simulate and check if the transaction can be included in the next block
        // self.block_builder.try_append(params.slot, params.tx)

        // TODO: check if there is enough time left in the current slot

        // TODO: If valid, broadcast the commitment to all connected relays

        Ok(serde_json::to_value(InclusionRequestResponse {
            request: params,
            signature: sidecar_signature,
        })?)
    }
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
