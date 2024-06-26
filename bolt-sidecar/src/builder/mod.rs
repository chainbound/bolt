use std::collections::HashMap;

use alloy_primitives::{B256, U256};
use compat::to_execution_payload_header;
use ethereum_consensus::{
    crypto::SecretKey as BlsSecretKey,
    ssz::prelude::{HashTreeRoot, List, MerkleizationError},
    types::mainnet::ExecutionPayload,
};
use reth_primitives::SealedHeader;

use crate::primitives::{BuilderBid, SignedBuilderBid};

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

/// Local builder instance that can ingest a sealed header and
/// create the corresponding builder bid ready for the Builder API.
#[derive(Debug)]
pub struct LocalBuilder {
    /// BLS credentials for the local builder. We use this to sign the
    /// payload bid submissions built by the sidecar.
    secret_key: BlsSecretKey,
    /// Cached payloads by block hash. This is used to respond to
    /// the builder API `getPayload` requests with the full block.
    cached_payloads: HashMap<B256, ExecutionPayload>,
}

impl LocalBuilder {
    /// Create a new local builder with the given secret key.
    pub fn new(secret_key: BlsSecretKey) -> Self {
        Self {
            secret_key,
            cached_payloads: Default::default(),
        }
    }

    /// Create a signed builder bid with the given value and header.
    pub fn create_signed_builder_bid(
        &self,
        value: U256,
        header: SealedHeader,
    ) -> Result<SignedBuilderBid, MerkleizationError> {
        let submission = BuilderBid {
            header: to_execution_payload_header(&header),
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

    /// Insert a payload into the cache.
    pub fn insert_payload(&mut self, hash: B256, payload: ExecutionPayload) {
        self.cached_payloads.insert(hash, payload);
    }

    /// Get the cached payload for the slot.
    pub fn cached_payload(&self, hash: B256) -> Option<&ExecutionPayload> {
        self.cached_payloads.get(&hash)
    }
}
