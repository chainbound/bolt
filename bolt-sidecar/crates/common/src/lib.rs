use lazy_static::lazy_static;

/// Utilities for retrying a future with backoff.
pub mod backoff;

/// A hash map-like bounded data structure with an additional scoring mechanism.
pub mod score_cache;

/// Secret key types wrappers for BLS, ECDSA and JWT.
pub mod secrets;

/// Time-related utilities.
pub mod time;

/// Utility functions for working with transactions.
pub mod transactions;

/// Built-time information about the sidecar binary.
pub mod built_info {
    // Docs: https://docs.rs/built/latest/built/
    // include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

lazy_static! {
    /// The version of the Bolt sidecar binary.
    pub static ref BOLT_SIDECAR_VERSION: String = "".to_string();
    // pub static ref BOLT_SIDECAR_VERSION: String =
    //     format!("v{}-{}", env!("CARGO_PKG_VERSION"), crate::built_info::GIT_COMMIT_HASH_SHORT.unwrap_or("unknown"));
}
