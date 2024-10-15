use std::{
    ffi::OsString,
    fs::{read_dir, DirEntry},
    io,
    path::{Path, PathBuf},
};

use alloy::primitives::FixedBytes;
use ethereum_consensus::{
    crypto::PublicKey as BlsPublicKey,
    deneb::{compute_fork_data_root, compute_signing_root, Root},
};
use eyre::Result;

use crate::{
    config::Chain,
    types::{DelegationMessage, KeystoreError},
};

// Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
pub const KEYSTORE_PASSWORD: &str = r#"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"#;

pub const KEYSTORES_DEFAULT_PATH: &str = "keys";

pub const COMMIT_BOOST_DOMAIN_MASK: [u8; 4] = [109, 109, 111, 67];

/// Parse the delegated public key from a string
pub fn parse_public_key(delegatee_pubkey: &str) -> Result<BlsPublicKey> {
    let hex_pk = delegatee_pubkey.strip_prefix("0x").unwrap_or(delegatee_pubkey);
    BlsPublicKey::try_from(hex::decode(hex_pk).expect("Failed to decode pubkey").as_slice())
        .map_err(|e| eyre::eyre!("Failed to parse public key '{}': {}", hex_pk, e))
}

/// Returns the paths of all the keystore files provided an optional `keys_path`, which defaults to
/// `keys`. `keys_path` is a relative path from the root of this cargo project
/// We're expecting a directory structure like:
/// ${keys_path}/
/// -- 0x1234.../validator.json
/// -- 0x5678.../validator.json
/// -- ...
/// Reference: https://github.com/chainbound/bolt/blob/4634ff905561009e4e74f9921dfdabf43717010f/bolt-sidecar/src/signer/keystore.rs#L109
pub fn keystore_paths(keys_path: Option<&str>) -> Result<Vec<PathBuf>> {
    // Create the path to the keystore directory, starting from the root of the project
    let keys_path = if let Some(keys_path) = keys_path {
        Path::new(&keys_path).to_path_buf()
    } else {
        let project_root = env!("CARGO_MANIFEST_DIR");
        Path::new(project_root).join(keys_path.unwrap_or(KEYSTORES_DEFAULT_PATH))
    };

    let json_extension = OsString::from("json");

    let mut keystores_paths = vec![];
    // Iter over the `keys` directory
    for entry in read_dir(keys_path)? {
        let path = read_path(entry)?;
        if path.is_dir() {
            for entry in read_dir(path)? {
                let path = read_path(entry)?;
                if path.is_file() && path.extension() == Some(&json_extension) {
                    keystores_paths.push(path);
                }
            }
        }
    }

    Ok(keystores_paths)
}

fn read_path(entry: std::result::Result<DirEntry, io::Error>) -> Result<PathBuf> {
    Ok(entry.map_err(KeystoreError::ReadFromDirectory)?.path())
}

/// Helper function to compute the signing root for a delegation message
pub fn compute_signing_root_for_delegation(
    delegation: &DelegationMessage,
    chain: &Chain,
) -> Result<FixedBytes<32>> {
    let message = delegation.digest();
    compute_signing_root(&message, compute_domain_from_mask(chain.fork_version()))
        .map_err(|e| eyre::eyre!("Failed to compute signing root: {}", e))
}

pub fn compute_domain_from_mask(fork_version: [u8; 4]) -> [u8; 32] {
    let mut domain = [0; 32];

    // Note: the application builder domain specs require the genesis_validators_root
    // to be 0x00 for any out-of-protocol message. The commit-boost domain follows the
    // same rule.
    let root = Root::default();
    let fork_data_root = compute_fork_data_root(fork_version, root).expect("valid fork data");

    domain[..4].copy_from_slice(&COMMIT_BOOST_DOMAIN_MASK);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}
