use std::{fs, io::Write, path::PathBuf};

use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use eyre::{Context, Result};
use serde::Serialize;
use tracing::info;

/// BoltManager contract bindings.
pub mod bolt_manager;

/// Utilities for working with DIRK remote keystores.
pub mod dirk;

/// Utilities and types for EIP-2335 keystore files.
pub mod keystore;

/// Utilities for signing and verifying messages.
pub mod signing;

/// Utilities for hashing messages and custom types.
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

/// Asks whether the user wants to proceed further. If not, the process is exited.
pub fn request_confirmation() {
    #[cfg(test)]
    return;

    loop {
        info!("Do you want to continue? (yes/no): ");

        print!("Answer: ");
        std::io::stdout().flush().expect("Failed to flush");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Failed to read input");

        let input = input.trim().to_lowercase();

        match input.as_str() {
            "yes" | "y" => {
                return;
            }
            "no" | "n" => {
                info!("Aborting");
                std::process::exit(0);
            }
            _ => {
                println!("Invalid input. Please type 'yes' or 'no'.");
            }
        }
    }
}
