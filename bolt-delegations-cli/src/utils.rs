use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, read_dir, DirEntry},
    io,
    path::{Path, PathBuf},
};

use alloy::primitives::FixedBytes;
use blst::{min_pk::Signature, BLST_ERROR};
use ethereum_consensus::{
    crypto::PublicKey as BlsPublicKey,
    deneb::{compute_fork_data_root, compute_signing_root, Root},
};
use eyre::{Context, Result};

use crate::{config::Chain, types::KeystoreError};

// Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
pub const KEYSTORE_PASSWORD: &str = r#"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"#;

pub const COMMIT_BOOST_DOMAIN_MASK: [u8; 4] = [109, 109, 111, 67];

/// The BLS Domain Separator used in Ethereum 2.0.
pub const BLS_DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub enum KeystoreSecret {
    /// When using a unique password for all validators in the keystore
    /// (e.g. for Prysm keystore)
    Unique(String),
    /// When using a directory to hold individual passwords for each validator
    /// according to the format: secrets/0x{validator_pubkey} = {password}
    Directory(HashMap<String, String>),
}

impl KeystoreSecret {
    /// Load the keystore passwords from a directory containing individual password files.
    pub fn from_directory(root_dir: String) -> Result<Self> {
        let mut secrets = HashMap::new();
        for entry in fs::read_dir(&root_dir)
            .wrap_err(format!("failed to read secrets directory. path: {}", &root_dir))?
        {
            let entry = entry.wrap_err("Failed to read secrets directory entry")?;
            let path = entry.path();

            let filename = path.file_name().expect("secret file name").to_string_lossy();
            let secret = fs::read_to_string(&path).wrap_err("Failed to read secret file")?;
            secrets.insert(filename.trim_start_matches("0x").to_string(), secret);
        }
        Ok(KeystoreSecret::Directory(secrets))
    }

    /// Set a unique password for all validators in the keystore.
    pub fn from_unique_password(password: String) -> Self {
        KeystoreSecret::Unique(password)
    }

    /// Get the password for the given validator public key.
    pub fn get(&self, validator_pubkey: &str) -> Option<&str> {
        match self {
            KeystoreSecret::Unique(password) => Some(password.as_str()),
            KeystoreSecret::Directory(secrets) => secrets.get(validator_pubkey).map(|s| s.as_str()),
        }
    }
}

/// Manual drop implementation to clear the password from memory
/// when the KeystoreSecret is dropped.
impl Drop for KeystoreSecret {
    fn drop(&mut self) {
        match self {
            KeystoreSecret::Unique(password) => {
                let bytes = unsafe { password.as_bytes_mut() };
                for b in bytes.iter_mut() {
                    *b = 0;
                }
            }
            KeystoreSecret::Directory(secrets) => {
                for secret in secrets.values_mut() {
                    let bytes = unsafe { secret.as_bytes_mut() };
                    for b in bytes.iter_mut() {
                        *b = 0;
                    }
                }
            }
        }
    }
}

/// Parse the delegated public key from a string
pub fn parse_public_key(delegatee_pubkey: &str) -> Result<BlsPublicKey> {
    let hex_pk = delegatee_pubkey.strip_prefix("0x").unwrap_or(delegatee_pubkey);
    BlsPublicKey::try_from(hex::decode(hex_pk).expect("Failed to decode pubkey").as_slice())
        .map_err(|e| eyre::eyre!("Failed to parse public key '{}': {}", hex_pk, e))
}

/// Returns the paths of all the keystore files provided in `keys_path`.
///
/// We're expecting a directory structure like:
/// ${keys_path}/
/// -- 0x1234.../validator.json
/// -- 0x5678.../validator.json
/// -- ...
/// Reference: https://github.com/chainbound/bolt/blob/4634ff905561009e4e74f9921dfdabf43717010f/bolt-sidecar/src/signer/keystore.rs#L109
pub fn keystore_paths(keys_path: &str) -> Result<Vec<PathBuf>> {
    let keys_path_buf = Path::new(keys_path).to_path_buf();
    let json_extension = OsString::from("json");

    let mut keystores_paths = vec![];
    // Iter over the `keys` directory
    for entry in read_dir(keys_path_buf)
        .wrap_err(format!("failed to read keys directory. path: {keys_path}"))?
    {
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

fn read_path(entry: io::Result<DirEntry>) -> Result<PathBuf> {
    Ok(entry.map_err(KeystoreError::ReadFromDirectory)?.path())
}

/// Helper function to compute the signing root for a message
pub fn compute_commit_boost_signing_root(
    message: [u8; 32],
    chain: &Chain,
) -> Result<FixedBytes<32>> {
    compute_signing_root(&message, compute_domain_from_mask(chain.fork_version()))
        .map_err(|e| eyre::eyre!("Failed to compute signing root: {}", e))
}

/// Compute the commit boost domain from the fork version
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

/// Verify the signature with the public key of the signer using the Commit Boost domain.
pub fn verify_commit_boost_root(
    pubkey: BlsPublicKey,
    root: [u8; 32],
    signature: &Signature,
    chain: &Chain,
) -> Result<()> {
    verify_root(pubkey, root, signature, compute_domain_from_mask(chain.fork_version()))
}

/// Verify the signature of the object with the given public key.
pub fn verify_root(
    pubkey: BlsPublicKey,
    root: [u8; 32],
    signature: &Signature,
    domain: [u8; 32],
) -> Result<()> {
    let signing_root = compute_signing_root(&root, domain)?;
    let pk = blst::min_pk::PublicKey::from_bytes(pubkey.as_ref()).unwrap();

    let res = signature.verify(true, signing_root.as_ref(), BLS_DST_PREFIX, &[], &pk, true);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(eyre::eyre!("bls verification failed"))
    }
}
