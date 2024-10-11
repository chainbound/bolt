//! An ERC-2335 keystore signer.

use std::{
    ffi::OsString,
    fmt::Debug,
    fs,
    path::{Path, PathBuf},
};

use alloy::rpc::types::beacon::constants::BLS_PUBLIC_KEY_BYTES_LEN;

use lighthouse_bls::Keypair;
use lighthouse_eth2_keystore::Keystore;
use ssz::Encode;

use crate::{builder::signature::compute_signing_root, crypto::bls::BLSSig, ChainConfig};

pub const KEYSTORES_DEFAULT_PATH: &str = "keys";

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("Failed to read keystore directory: {0}")]
    ReadFromDirectory(#[from] std::io::Error),
    #[error("Failed to read keystore from JSON file {0}: {1}")]
    ReadFromJSON(PathBuf, String),
    #[error("Failed to decrypt keypair from JSON file {0} with the provided password: {1}")]
    KeypairDecryption(PathBuf, String),
    #[error("Could not find private key associated to public key {0}")]
    UnknownPublicKey(String),
    #[error("Invalid signature key length. Signature: {0}. Message: {1}")]
    SignatureLength(String, String),
}

type Result<T> = std::result::Result<T, KeystoreError>;

#[derive(Clone)]
pub struct KeystoreSigner {
    keypairs: Vec<Keypair>,
    chain: ChainConfig,
}

impl KeystoreSigner {
    pub fn new(keys_path: Option<&str>, password: &[u8], chain: ChainConfig) -> Result<Self> {
        let keystores_paths = keystore_paths(keys_path)?;
        let mut keypairs = Vec::with_capacity(keystores_paths.len());

        for path in keystores_paths {
            let keypair = Keystore::from_json_file(path.clone())
                .map_err(|e| KeystoreError::ReadFromJSON(path.clone(), format!("{e:?}")))?
                .decrypt_keypair(password)
                .map_err(|e| KeystoreError::KeypairDecryption(path.clone(), format!("{e:?}")))?;
            keypairs.push(keypair);
        }

        Ok(Self { keypairs, chain })
    }

    pub fn sign_commit_boost_root(
        &self,
        root: [u8; 32],
        public_key: [u8; BLS_PUBLIC_KEY_BYTES_LEN],
    ) -> Result<BLSSig> {
        self.sign_root(root, public_key, self.chain.commit_boost_domain())
    }

    fn sign_root(
        &self,
        root: [u8; 32],
        public_key: [u8; BLS_PUBLIC_KEY_BYTES_LEN],
        domain: [u8; 32],
    ) -> Result<BLSSig> {
        let sk = self
            .keypairs
            .iter()
            // `as_ssz_bytes` returns the raw bytes we need
            .find(|kp| kp.pk.as_ssz_bytes() == public_key.as_ref())
            .ok_or(KeystoreError::UnknownPublicKey(hex::encode(public_key)))?;

        let signing_root = compute_signing_root(root, domain);

        let sig = sk.sk.sign(signing_root.into()).as_ssz_bytes();
        let sig = BLSSig::try_from(sig.as_slice())
            .map_err(|e| KeystoreError::SignatureLength(hex::encode(sig), format!("{e:?}")))?;

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
fn keystore_paths(keys_path: Option<&str>) -> Result<Vec<PathBuf>> {
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
    for entry in fs::read_dir(keys_path).map_err(KeystoreError::ReadFromDirectory)? {
        let path = entry.map_err(KeystoreError::ReadFromDirectory)?.path();
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

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use blst::min_pk::SecretKey;

    use crate::{signer::local::LocalSigner, ChainConfig};

    use super::{KeystoreSigner, KEYSTORES_DEFAULT_PATH};
    /// The str path of the root of the project
    pub const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn test_keystore_signer() {
        // 0. Test data setup

        // Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
        let test_keystore_json = r#"
            {
                "crypto": {
                    "kdf": {
                        "function": "scrypt",
                        "params": {
                            "dklen": 32,
                            "n": 262144,
                            "p": 1,
                            "r": 8,
                            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                        },
                        "message": ""
                    },
                    "checksum": {
                        "function": "sha256",
                        "params": {},
                        "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                    },
                    "cipher": {
                        "function": "aes-128-ctr",
                        "params": {
                            "iv": "264daa3f303d7259501c93d997d84fe6"
                        },
                        "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                    }
                },
                "description": "This is a test keystore that uses scrypt to secure the secret.",
                "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "path": "m/12381/60/3141592653/589793238",
                "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
                "version": 4
            }
        "#;
        // Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
        let keystore_password = r#"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"#;
        let keystore_public_key = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
        let keystore_publlc_key_bytes: [u8; 48] = [
            0x96, 0x12, 0xd7, 0xa7, 0x27, 0xc9, 0xd0, 0xa2, 0x2e, 0x18, 0x5a, 0x1c, 0x76, 0x84,
            0x78, 0xdf, 0xe9, 0x19, 0xca, 0xda, 0x92, 0x66, 0x98, 0x8c, 0xb3, 0x23, 0x59, 0xc1,
            0x1f, 0x2b, 0x7b, 0x27, 0xf4, 0xae, 0x40, 0x40, 0x90, 0x23, 0x82, 0xae, 0x29, 0x10,
            0xc1, 0x5e, 0x2b, 0x42, 0x0d, 0x07,
        ];
        let keystore_secret_key =
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let chain_config = ChainConfig::mainnet();

        // 1. Create a temp directory with the keystore and create a signer from it

        let path_str = format!("{}/{}", CARGO_MANIFEST_DIR, KEYSTORES_DEFAULT_PATH);
        let tmp_dir =
            tempfile::TempDir::with_prefix_in("0xdeadbeefdeadbeefdeadbeefdeadbeef", path_str)
                .expect("to create temp dir");

        // NOTE: it is sufficient to create a temp dir, then we can create a file as usual and it
        // will be dropped correctly
        let mut tmp_file = File::create_new(tmp_dir.path().join("voting-keystore.json"))
            .expect("to create new file");

        tmp_file.write_all(test_keystore_json.as_bytes()).expect("to write to temp file");

        for entry in tmp_dir.path().read_dir().expect("to read tmp dir") {
            let mut path = entry.expect("to read entry").path();
            println!("inside loop: {:?}", path);
            let extenstion =
                path.extension().expect("to get extension").to_str().expect("to convert to str");

            if extenstion.contains("tmp") {
                path.set_extension("json");
                println!("path: {:?}", path);
                break;
            }
        }

        let keystore_signer = KeystoreSigner::new(None, keystore_password.as_bytes(), chain_config)
            .expect("to create keystore signer");

        assert_eq!(keystore_signer.keypairs.len(), 1);
        assert_eq!(
            keystore_signer.keypairs.first().expect("to get keypair").pk.to_string(),
            keystore_public_key
        );

        // 2. Sign a message with the signer and check the signature

        let keystore_sk_bls = SecretKey::from_bytes(
            hex::decode(keystore_secret_key).expect("to decode secret key").as_slice(),
        )
        .expect("to create secret key");

        let local_signer = LocalSigner::new(keystore_sk_bls, chain_config);

        let sig_local = local_signer.sign_commit_boost_root([0; 32]).expect("to sign message");
        let sig_keystore = keystore_signer
            .sign_commit_boost_root([0; 32], keystore_publlc_key_bytes)
            .expect("to sign message");
        assert_eq!(sig_local, sig_keystore);
    }
}
