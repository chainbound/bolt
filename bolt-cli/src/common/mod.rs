use std::{fs, path::PathBuf};

use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use eyre::{Context, Result};
use serde::Serialize;

/// BoltManager contract bindings.
pub mod bolt_manager;

/// Utilities for working with DIRK remote keystores.
pub mod dirk;

/// Utilities and types for EIP-2335 keystore files.
pub mod keystore;

/// Utilities for signing and verifying messages.
pub mod signing;

pub mod hash;

/// Parse a BLS public key from a string
pub fn parse_bls_public_key(delegatee_pubkey: &str) -> Result<BlsPublicKey> {
    let hex_pk = delegatee_pubkey.strip_prefix("0x").unwrap_or(delegatee_pubkey);
    BlsPublicKey::try_from(
        hex::decode(hex_pk).wrap_err("Failed to hex-decode delegatee pubkey")?.as_slice(),
    )
    .map_err(|e| eyre::eyre!("Failed to parse delegatee public key '{}': {}", hex_pk, e))
}

/// Write some serializable data to an output json file
pub fn write_to_file<T: Serialize>(out: &str, data: &T) -> Result<()> {
    let out_path = PathBuf::from(out);
    let out_file = fs::File::create(out_path)?;
    serde_json::to_writer_pretty(out_file, data)?;
    Ok(())
}
