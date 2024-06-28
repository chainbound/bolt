use alloy_primitives::{Address, U256};
use ethereum_consensus::{
    crypto::SecretKey as BlsSecretKey,
    ssz::prelude::{HashTreeRoot, List, MerkleizationError},
};
use payload_builder::FallbackPayloadBuilder;
use reth_primitives::{SealedHeader, TransactionSigned};

use crate::primitives::{
    BuilderBid, GetPayloadResponse, PayloadAndBid, PayloadAndBlobs, SignedBuilderBid,
};

/// Basic block template handler that can keep track of
/// the local commitments according to protocol validity rules.
pub mod template;
pub use template::BlockTemplate;

/// Compatibility types and utilities between Alloy, Reth,
/// Ethereum-consensus and other crates.
#[doc(hidden)]
mod compat;

/// Fallback Payload builder agent that leverages the engine API's
/// `engine_newPayloadV3` response error to produce a valid payload.
pub mod payload_builder;

/// Deprecated. TODO: remove
pub mod state_root;

/// Deprecated simulation manager. TODO: remove
pub mod call_trace_manager;
pub use call_trace_manager::{CallTraceHandle, CallTraceManager};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum BuilderError {
    #[error("Failed to parse from integer: {0}")]
    Parse(#[from] std::num::ParseIntError),
    #[error("Failed to de/serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Failed to decode hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Invalid JWT: {0}")]
    Jwt(#[from] reth_rpc_layer::JwtError),
    #[error("Failed HTTP request: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed while fetching from RPC: {0}")]
    Transport(#[from] alloy_transport::TransportError),
    #[error("Failed in SSZ merkleization: {0}")]
    Merkleization(#[from] MerkleizationError),
    #[error("Failed to parse hint from engine response: {0}")]
    InvalidEngineHint(String),
    #[error("Failed to build payload: {0}")]
    Custom(String),
}

/// Local builder instance that can ingest a sealed header and
/// create the corresponding builder bid ready for the Builder API.
#[derive(Debug)]
pub struct LocalBuilder {
    /// BLS credentials for the local builder. We use this to sign the
    /// payload bid submissions built by the sidecar.
    secret_key: BlsSecretKey,
    /// Async fallback payload builder to generate valid payloads with
    /// the engine API's `engine_newPayloadV3` response error.
    fallback_builder: FallbackPayloadBuilder,
}

impl LocalBuilder {
    /// Create a new local builder with the given secret key.
    pub fn new(
        secret_key: BlsSecretKey,
        execution_rpc_url: &str,
        engine_rpc_url: &str,
        engine_jwt_secret: &str,
        fee_recipient: Address,
    ) -> Self {
        Self {
            secret_key,
            fallback_builder: FallbackPayloadBuilder::new(
                engine_jwt_secret,
                fee_recipient,
                execution_rpc_url,
                engine_rpc_url,
            ),
        }
    }

    /// Build a new payload with the given transactions. This method will
    /// return a signed builder bid that can be submitted to the Builder API.
    pub async fn build_new_local_payload(
        &mut self,
        transactions: Vec<TransactionSigned>,
    ) -> Result<PayloadAndBid, BuilderError> {
        // 1. build a fallback payload with the given transactions, on top of
        // the current head of the chain
        let sealed_block = self
            .fallback_builder
            .build_fallback_payload(transactions)
            .await?;

        // NOTE: we use a big value for the bid to ensure it gets chosen by mev-boost.
        // the client has no way to actually verify this, and we don't need to trust
        // an external relay as this block is self-built, so the fake bid value is fine.
        let value = U256::from(1_000_000_000_000_000_000u128);

        let eth_payload = compat::to_consensus_execution_payload(&sealed_block);
        let payload_and_blobs = PayloadAndBlobs {
            execution_payload: eth_payload,
            // TODO: add included blobs here
            blobs_bundle: None,
        };

        // 2. create a signed builder bid with the sealed block header we just created
        let signed_bid = self.create_signed_builder_bid(value, sealed_block.header)?;

        // 3. prepare a get_payload response for when the beacon node will ask for it
        let Some(get_payload_res) =
            GetPayloadResponse::try_from_execution_payload(&payload_and_blobs)
        else {
            return Err(BuilderError::Custom(
                "Failed to build get_payload response: invalid fork version".to_string(),
            ));
        };

        Ok(PayloadAndBid {
            bid: signed_bid,
            payload: get_payload_res,
        })
    }

    /// transform a sealed header into a signed builder bid using
    /// the local builder's BLS key.
    fn create_signed_builder_bid(
        &self,
        value: U256,
        header: SealedHeader,
    ) -> Result<SignedBuilderBid, BuilderError> {
        let submission = BuilderBid {
            header: compat::to_execution_payload_header(&header),
            blob_kzg_commitments: List::default(),
            public_key: self.secret_key.public_key(),
            value,
        };

        let signature = self.secret_key.sign(submission.hash_tree_root()?.as_ref());

        Ok(SignedBuilderBid {
            message: submission,
            signature,
        })
    }
}
