use lazy_static::lazy_static;

use crate::built_info;

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

lazy_static! {
    /// The version of the Bolt sidecar binary.
    ///
    /// Example format: "v0.1.0-alpha-abcdefg"
    pub static ref BOLT_SIDECAR_VERSION: String = format!(
        "v{}{}",
        built_info::PKG_VERSION,
        // Include the git commit hash, if available
        built_info::GIT_COMMIT_HASH_SHORT.map(|s| format!("-{}", s)).unwrap_or_else(|| {
            // If built info is not available, try the environment variable
            let from_env = std::env::var("GIT_COMMIT_HASH").map(|s| {
                // take only the first 7 characters of the full hash
                format!("-{}", s.chars().take(7).collect::<String>())
            });

            // If the environment variable is not set either, return an empty string
            from_env.unwrap_or_default()
        })
    );
}
