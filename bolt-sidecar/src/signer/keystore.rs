//! An ERC-2335 keystore signer.

use std::{
    ffi::OsString,
    fmt::Debug,
    fs,
    path::{Path, PathBuf},
};

use alloy::rpc::types::beacon::constants::BLS_PUBLIC_KEY_BYTES_LEN;
use eyre::eyre;

use lighthouse_bls::Keypair;
use lighthouse_eth2_keystore::Keystore;
use ssz::Encode;

use crate::crypto::bls::BLSSig;

pub const KEYSTORES_DEFAULT_PATH: &str = "keys";

#[derive(Clone)]
pub struct KeystoreSigner {
    keypairs: Vec<Keypair>,
}

impl KeystoreSigner {
    pub fn new(keys_path: Option<&str>, password: &[u8]) -> eyre::Result<Self> {
        let keystores_paths = keystore_paths(keys_path)?;
        let mut keypairs = Vec::with_capacity(keystores_paths.len());

        for path in keystores_paths {
            let keypair = Keystore::from_json_file(path.clone())
                .map_err(|e| {
                    eyre!(format!("err while reading keystore json file {:?}: {:?}", path, e))
                })?
                .decrypt_keypair(password)
                .map_err(|e| {
                    eyre!(format!(
                        "err while decrypting keypair from json file {:?}: {:?}",
                        path, e
                    ))
                })?;
            keypairs.push(keypair);
        }

        Ok(Self { keypairs })
    }

    pub fn sign_commit_boost_root(
        &self,
        root: [u8; 32],
        public_key: [u8; BLS_PUBLIC_KEY_BYTES_LEN],
    ) -> eyre::Result<BLSSig> {
        let sk = self
            .keypairs
            .iter()
            // NOTE: need to check if this method returns just the raw bytes
            .find(|kp| kp.pk.as_ssz_bytes() == public_key.as_ref())
            .ok_or(eyre!("could not find private key associated to public key"))?;

        let sig = hex::decode(sk.sk.sign(root.into()).to_string())?;
        let sig =
            BLSSig::try_from(sig.as_slice()).map_err(|_| eyre!("invalid signature length"))?;

        Ok(sig)
    }
}

impl Debug for KeystoreSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field(
                "pubkeys",
                &self.keypairs.iter().map(|kp| kp.pk.as_hex_string()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Returns the paths of all the keystore files provided an optional `keys_path`, which defaults to
/// `keys`. `keys_path` is a relative path from the root of this cargo project
/// We're expecting a directory structure like:
/// ${keys_path}/
/// -- 0x1234.../validator.json
/// -- 0x5678.../validator.json
/// -- ...
fn keystore_paths(keys_path: Option<&str>) -> Result<Vec<PathBuf>, eyre::Error> {
    // Create the path to the keystore directory, starting from the root of the project
    let project_root = env!("CARGO_MANIFEST_DIR");
    let keys_path = Path::new(project_root).join(keys_path.unwrap_or(KEYSTORES_DEFAULT_PATH));

    let json_extension = OsString::from("json");

    let mut keystores_paths = vec![];
    // Iter over the `keys` directory
    for entry in fs::read_dir(keys_path)? {
        let path = entry?.path();
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let path = entry?.path();
                if path.is_file() && path.extension() == Some(&json_extension) {
                    keystores_paths.push(path);
                }
            }
        }
    }

    Ok(keystores_paths)
}
