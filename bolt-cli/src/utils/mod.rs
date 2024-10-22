use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use eyre::{Context, Result};

/// Utilities and types for EIP-2335 keystore files.
pub mod keystore;

/// Utilities for signing and verifying messages.
pub mod signing;

/// Parse a BLS public key from a string
pub fn parse_public_key(delegatee_pubkey: &str) -> Result<BlsPublicKey> {
    let hex_pk = delegatee_pubkey.strip_prefix("0x").unwrap_or(delegatee_pubkey);
    BlsPublicKey::try_from(hex::decode(hex_pk).wrap_err("Failed to hex-decode pubkey")?.as_slice())
        .map_err(|e| eyre::eyre!("Failed to parse public key '{}': {}", hex_pk, e))
}
