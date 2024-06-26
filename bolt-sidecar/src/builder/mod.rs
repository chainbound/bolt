use crate::primitives::{BuilderBid, SignedBuilderBid};
use alloy_primitives::U256;
use compat::to_execution_payload_header;
use ethereum_consensus::{
    crypto::SecretKey as BlsSecretKey,
    ssz::prelude::{ssz_rs, HashTreeRoot, List},
};
use reth_primitives::SealedHeader;

pub mod template;
pub use template::BlockTemplate;

/// Compatibility types and utilities between Alloy, Reth, Ethereum-consensus
/// and other crates.
#[doc(hidden)]
mod compat;

pub mod payload_builder;

pub mod state_root;

pub mod call_trace_manager;
pub use call_trace_manager::{CallTraceHandle, CallTraceManager};

/// Local builder instance that can ingest a sealed header and
/// create the corresponding builder bid ready for the Builder API.
#[derive(Debug)]
pub struct LocalBuilder {
    secret_key: BlsSecretKey,
}

impl LocalBuilder {
    /// Create a new local builder with the given secret key.
    pub fn new(secret_key: BlsSecretKey) -> Self {
        Self { secret_key }
    }

    /// Create a signed builder bid with the given value and header.
    pub fn create_signed_builder_bid(
        &self,
        value: U256,
        header: SealedHeader,
    ) -> Result<SignedBuilderBid, ssz_rs::MerkleizationError> {
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
}
