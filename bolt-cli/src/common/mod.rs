use std::{fs, path::PathBuf, str::FromStr};

use alloy::{
    contract::Error as ContractError,
    dyn_abi::DynSolType,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Bytes, U256},
    sol_types::SolInterface,
    transports::TransportError,
};
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use eyre::{Context, ContextCompat, Result};
use inquire::{error::InquireError, Confirm};
use reqwest::Url;
use serde::Serialize;
use tracing::{error, info};

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

/// Utilities for working with Consensys' Web3Signer remote keystore.
pub mod web3signer;

/// Parses an ether value from a string.
///
/// The amount can be tagged with a unit, e.g. "1ether".
///
/// If the string represents an untagged amount (e.g. "100") then
/// it is interpreted as wei.
///
/// This Snippet is copied from Foundry's Cast CLI.
/// Ref: https://github.com/foundry-rs/foundry/blob/206dab285437bd6889463ab006b6a5fb984079d8/crates/cli/src/utils/mod.rs#L137
pub fn parse_ether_value(value: &str) -> Result<U256> {
    Ok(if value.starts_with("0x") {
        U256::from_str_radix(value, 16)?
    } else {
        DynSolType::coerce_str(&DynSolType::Uint(256), value)?
            .as_uint()
            .wrap_err("Could not parse ether value from string")?
            .0
    })
}

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

/// Try to decode a contract error into a specific Solidity error interface.
/// If the error cannot be decoded or it is not a contract error, return the original error.
///
/// Example usage:
///
/// ```rust no_run
/// sol! {
///    library ErrorLib {
///       error SomeError(uint256 code);
///    }
/// }
///
/// // call a contract that may return an error with the SomeError interface
/// let returndata = match myContract.call().await {
///    Ok(returndata) => returndata,
///    Err(err) => {
///         let decoded_error = try_decode_contract_error::<ErrorLib::ErrorLibError>(err)?;
///        // handle the decoded error however you want; for example, return it
///         return Err(decoded_error);
///    },
/// }
/// ```
pub fn try_parse_contract_error<T: SolInterface>(error: ContractError) -> Result<T, ContractError> {
    match error {
        ContractError::TransportError(TransportError::ErrorResp(resp)) => {
            let Some(data) = resp.data else {
                return Err(ContractError::TransportError(TransportError::ErrorResp(resp)));
            };

            let data = data.get().trim_matches('"');
            let data = Bytes::from_str(data).unwrap_or_default();

            T::abi_decode(&data, true).map_err(Into::into)
        }

        // For any other error, return the original error
        _ => Err(error),
    }
}

/// Asks whether the user wants to proceed further. If not, the process is exited.
#[allow(unreachable_code)]
pub fn request_confirmation() {
    // Skip confirmation in tests
    #[cfg(test)]
    return;

    Confirm::new("Do you want to continue? (yes/no):")
        .prompt()
        .map(|proceed| {
            if proceed {
                return;
            }
            info!("Aborting");
            std::process::exit(0);
        })
        .unwrap_or_else(|err| match err {
            InquireError::OperationCanceled => {
                // User pressed ESC, a shorthand for "no"
                info!("Aborting");
                std::process::exit(0);
            }
            InquireError::OperationInterrupted => {
                // Triggered a SIGINT via Ctrl-C
                std::process::exit(130);
            }
            _ => {
                error!("aborting due to unexpected error: {}", err);
                std::process::exit(1);
            }
        })
}

/// Determines the RPC URL to use. If `dry_run` is enabled, it spawns an `Anvil` instance and
/// returns its endpoint. Otherwise, returns the original `rpc_url`.
pub(crate) fn handle_rpc_dry_run(
    rpc_url: Url,
    dry_run: bool,
) -> eyre::Result<(Url, Option<AnvilInstance>)> {
    if !dry_run {
        return Ok((rpc_url, None));
    }

    let anvil = Anvil::new()
        .fork(rpc_url)
        .try_spawn()
        .map_err(|e| eyre::eyre!("[dry-run] Failed to spawn Anvil: {}", e))?;

    let anvil_url = anvil.endpoint_url();
    info!("[dry-run] Anvil endpoint URL: {}", anvil_url);

    Ok((anvil_url, Some(anvil)))
}

/// drop provided `AnvilInstance` to control resource consumption
pub fn shutdown_anvil(anvil: Option<AnvilInstance>) {
    if let Some(anvil_instance) = anvil {
        info!("[dry-run] Shutting down Anvil instance.");
        drop(anvil_instance);
    }
}
