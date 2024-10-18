//! An ERC-2335 keystore signer.

use std::{
    collections::HashSet,
    ffi::OsString,
    fmt::Debug,
    fs::{self, DirEntry, ReadDir},
    io,
    path::PathBuf,
};

use alloy::rpc::types::beacon::constants::BLS_PUBLIC_KEY_BYTES_LEN;

use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use lighthouse_bls::Keypair;
use lighthouse_eth2_keystore::Keystore;
use ssz::Encode;

use crate::{builder::signature::compute_signing_root, crypto::bls::BLSSig, ChainConfig};

use super::SignerResult;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("failed to read keystore directory: {0}")]
    ReadFromDirectory(#[from] std::io::Error),
    #[error("failed to read keystore from JSON file {0}: {1}")]
    ReadFromJSON(PathBuf, String),
    #[error("failed to read keystore secret from file: {0}")]
    ReadFromSecretFile(String),
    #[error("failed to decrypt keypair from JSON file {0} with the provided password: {1}")]
    KeypairDecryption(PathBuf, String),
    #[error("could not find private key associated to public key {0}")]
    UnknownPublicKey(String),
    #[error("invalid signature key length -- signature: {0} -- message: {1}")]
    SignatureLength(String, String),
}

#[derive(Clone)]
pub struct KeystoreSigner {
    keypairs: Vec<Keypair>,
    chain: ChainConfig,
}

impl KeystoreSigner {
    /// Creates a new `KeystoreSigner` from the keystore files in the `keys_path` directory.
    pub fn from_password(
        keys_path: &PathBuf,
        password: &[u8],
        chain: ChainConfig,
    ) -> SignerResult<Self> {
        // Create the path to the keystore directory, starting from the root of the project
        let keystores_paths = find_json_keystores(keys_path)?;
        let mut keypairs = Vec::with_capacity(keystores_paths.len());

        for path in keystores_paths {
            let keystore = Keystore::from_json_file(path.clone())
                .map_err(|e| KeystoreError::ReadFromJSON(path.clone(), format!("{e:?}")))?;
            let keypair = keystore
                .decrypt_keypair(password)
                .map_err(|e| KeystoreError::KeypairDecryption(path.clone(), format!("{e:?}")))?;
            keypairs.push(keypair);
        }

        Ok(Self { keypairs, chain })
    }

    #[allow(clippy::ptr_arg)]
    pub fn from_secrets_directory(
        keys_path: &PathBuf,
        secrets_path: &PathBuf,
        chain: ChainConfig,
    ) -> SignerResult<Self> {
        let keystores_paths = find_json_keystores(keys_path)?;

        let mut keypairs = Vec::with_capacity(keystores_paths.len());

        for path in keystores_paths {
            let keystore = Keystore::from_json_file(path.clone())
                .map_err(|e| KeystoreError::ReadFromJSON(path.clone(), format!("{e:?}")))?;

            let pubkey = format!("0x{}", keystore.pubkey());

            let mut secret_path = secrets_path.clone();
            secret_path.push(pubkey);

            let password = fs::read_to_string(secret_path)
                .map_err(|e| KeystoreError::ReadFromSecretFile(format!("{e:?}")))?;

            let keypair = keystore
                .decrypt_keypair(password.as_bytes())
                .map_err(|e| KeystoreError::KeypairDecryption(path.clone(), format!("{e:?}")))?;
            keypairs.push(keypair);
        }

        Ok(Self { keypairs, chain })
    }

    /// Returns the public keys of the keypairs in the keystore.
    pub fn pubkeys(&self) -> HashSet<BlsPublicKey> {
        self.keypairs
            .iter()
            .map(|kp| {
                BlsPublicKey::try_from(kp.pk.serialize().to_vec().as_ref()).expect("valid pubkey")
            })
            .collect::<HashSet<_>>()
    }

    /// Signs a message with the keystore signer and the Commit Boost domain
    pub fn sign_commit_boost_root(
        &self,
        root: [u8; 32],
        public_key: [u8; BLS_PUBLIC_KEY_BYTES_LEN],
    ) -> SignerResult<BLSSig> {
        self.sign_root(root, public_key, self.chain.commit_boost_domain())
    }

    /// Signs a message with the keystore signer.
    fn sign_root(
        &self,
        root: [u8; 32],
        public_key: [u8; BLS_PUBLIC_KEY_BYTES_LEN],
        domain: [u8; 32],
    ) -> SignerResult<BLSSig> {
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
fn find_json_keystores(keys_path: &PathBuf) -> SignerResult<Vec<PathBuf>> {
    let json_extension = OsString::from("json");

    let mut keystores_paths = vec![];
    // Iter over the `keys` directory
    for entry in read_dir(keys_path)? {
        let path = read_path(entry)?;
        if path.is_dir() {
            for entry in read_dir(&path)? {
                let path = read_path(entry)?;
                if path.is_file() && path.extension() == Some(&json_extension) {
                    keystores_paths.push(path);
                }
            }
        }
    }

    Ok(keystores_paths)
}

fn read_dir(path: &PathBuf) -> SignerResult<ReadDir> {
    Ok(fs::read_dir(path).map_err(KeystoreError::ReadFromDirectory)?)
}

fn read_path(entry: std::result::Result<DirEntry, io::Error>) -> SignerResult<PathBuf> {
    Ok(entry.map_err(KeystoreError::ReadFromDirectory)?.path())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::Write,
        path::{Path, PathBuf},
    };

    use blst::min_pk::SecretKey;

    use crate::{signer::local::LocalSigner, ChainConfig};

    use super::KeystoreSigner;
    /// The str path of the root of the project
    pub const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

    const KEYSTORES_DEFAULT_PATH_TEST: &str = "test_data/keys";
    const KEYSTORES_SECRETS_DEFAULT_PATH_TEST: &str = "test_data/secrets";

    /// If `path` is `Some`, returns a clone of it. Otherwise, returns the path to the `fallback_relative_path`
    /// starting from the root of the cargo project.
    fn make_path(relative_path: &str) -> PathBuf {
        let project_root = env!("CARGO_MANIFEST_DIR");
        Path::new(project_root).join(relative_path)
    }

    #[test]
    fn test_keystore_signer() {
        // 0. Test data setup

        // Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
        let tests_keystore_json = [
            r#"
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
        "#,
            r#"
            {
                "crypto": {
                    "kdf": {
                        "function": "pbkdf2",
                        "params": {
                            "dklen": 32,
                            "c": 262144,
                            "prf": "hmac-sha256",
                            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                        },
                        "message": ""
                    },
                    "checksum": {
                        "function": "sha256",
                        "params": {},
                        "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                    },
                    "cipher": {
                        "function": "aes-128-ctr",
                        "params": {
                            "iv": "264daa3f303d7259501c93d997d84fe6"
                        },
                        "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                    }
                },
                "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
                "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "path": "m/12381/60/0/0",
                "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
                "version": 4
            }
        "#,
        ];

        // Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
        let password = r#"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"#;
        let public_key = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
        let public_key_bytes: [u8; 48] = [
            0x96, 0x12, 0xd7, 0xa7, 0x27, 0xc9, 0xd0, 0xa2, 0x2e, 0x18, 0x5a, 0x1c, 0x76, 0x84,
            0x78, 0xdf, 0xe9, 0x19, 0xca, 0xda, 0x92, 0x66, 0x98, 0x8c, 0xb3, 0x23, 0x59, 0xc1,
            0x1f, 0x2b, 0x7b, 0x27, 0xf4, 0xae, 0x40, 0x40, 0x90, 0x23, 0x82, 0xae, 0x29, 0x10,
            0xc1, 0x5e, 0x2b, 0x42, 0x0d, 0x07,
        ];
        let secret_key = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let chain_config = ChainConfig::mainnet();

        let keystore_path =
            format!("{}/{}/{}", CARGO_MANIFEST_DIR, KEYSTORES_DEFAULT_PATH_TEST, public_key);
        let keystore_path = PathBuf::from(keystore_path);

        for test_keystore_json in tests_keystore_json {
            // 1. Write the keystore in a `test-voting-keystore.json` file so we test both scrypt and PBDKF2

            let mut tmp_keystore_file =
                File::create(keystore_path.join("test-voting-keystore.json"))
                    .expect("to create new keystore file");

            tmp_keystore_file
                .write_all(test_keystore_json.as_bytes())
                .expect("to write to temp file");

            // Create a file for the secret, we are going to test it as well
            let keystores_secrets_path = make_path(KEYSTORES_SECRETS_DEFAULT_PATH_TEST);
            let mut tmp_secret_file = File::create(keystores_secrets_path.join(public_key))
                .expect("to create secret file");

            tmp_secret_file.write_all(password.as_bytes()).expect("to write to temp file");

            let keys_path = make_path(KEYSTORES_DEFAULT_PATH_TEST);
            let keystore_signer_from_password =
                KeystoreSigner::from_password(&keys_path, password.as_bytes(), chain_config)
                    .expect("to create keystore signer from password");

            assert_eq!(keystore_signer_from_password.keypairs.len(), 3);
            assert_eq!(
                keystore_signer_from_password
                    .keypairs
                    .first()
                    .expect("to get keypair")
                    .pk
                    .to_string(),
                public_key
            );

            let keystore_signer_from_directory = KeystoreSigner::from_secrets_directory(
                &keys_path,
                &keystores_secrets_path,
                chain_config,
            )
            .expect("to create keystore signer from secrets dir");

            assert_eq!(keystore_signer_from_directory.keypairs.len(), 3);
            assert_eq!(
                keystore_signer_from_directory
                    .keypairs
                    .first()
                    .expect("to get keypair")
                    .pk
                    .to_string(),
                public_key
            );

            // 2. Sign a message with the signer and check the signature

            let keystore_sk_bls = SecretKey::from_bytes(
                hex::decode(secret_key).expect("to decode secret key").as_slice(),
            )
            .expect("to create secret key");

            let local_signer = LocalSigner::new(keystore_sk_bls, chain_config);

            let sig_local = local_signer.sign_commit_boost_root([0; 32]).expect("to sign message");
            let sig_keystore = keystore_signer_from_password
                .sign_commit_boost_root([0; 32], public_key_bytes)
                .expect("to sign message");
            assert_eq!(sig_local, sig_keystore);
        }
    }
}
