use std::{fs, path::PathBuf};

use clap::Parser;
use ethereum_consensus::crypto::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
};
use eyre::Result;
use lighthouse_eth2_keystore::Keystore;
use serde::Serialize;

pub mod config;
use config::{Action, Chain, Commands, KeySource, Opts};

pub mod types;
use types::{
    DelegationMessage, KeystoreError, RevocationMessage, SignedDelegation, SignedMessage,
    SignedRevocation,
};

pub mod utils;
use utils::{compute_commit_boost_signing_root, keystore_paths, parse_public_key};

fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    let cli = Opts::parse();

    match cli.command {
        Commands::Generate { delegatee_pubkey, out, chain, source, action } => match source {
            KeySource::Local { secret_keys } => {
                let delegatee = parse_public_key(&delegatee_pubkey)?;
                let messages = generate_from_local_keys(&secret_keys, delegatee, &chain, action)?;

                write_to_file(&out, &messages)?;
                println!("Signed delegation messages generated and saved to {}", out);
            }
            KeySource::Keystore { keystore_path, keystore_password } => {
                let delegatee = parse_public_key(&delegatee_pubkey)?;
                let messages = generate_from_keystore(
                    &keystore_path,
                    &keystore_password,
                    delegatee,
                    &chain,
                    action,
                )?;

                write_to_file(&out, &messages)?;
                println!("Signed delegation messages generated and saved to {}", out);
            }
        },
    }
    Ok(())
}

/// Generate signed delegations/revocations using local BLS private keys
///
/// - Use the provided private keys from either CLI or env variable
/// - Create message
/// - Compute the signing roots and sign the messages
/// - Return the signed messages
fn generate_from_local_keys(
    secret_keys: &Vec<String>,
    delegatee_pubkey: BlsPublicKey,
    chain: &Chain,
    action: Action,
) -> Result<Vec<SignedMessage>> {
    let mut signed_messages = Vec::with_capacity(secret_keys.len());

    for sk in secret_keys {
        let sk = BlsSecretKey::try_from(sk.trim().to_string())?;

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(sk.public_key(), delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), chain)?;
                let signature = sk.sign(signing_root.0.as_ref());
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed))
            }
            Action::Revoke => {
                let message = RevocationMessage::new(sk.public_key(), delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), chain)?;
                let signature = sk.sign(signing_root.0.as_ref());
                let signed = SignedRevocation { message, signature };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }
    }

    Ok(signed_messages)
}

/// Generate signed delegations/revocations using a keystore file
///
/// - Read the keystore file
/// - Decrypt the keypairs using the password
/// - Create messages
/// - Compute the signing roots and sign the message
/// - Return the signed message
fn generate_from_keystore(
    keys_path: &str,
    password: &str,
    delegatee_pubkey: BlsPublicKey,
    chain: &Chain,
    action: Action,
) -> Result<Vec<SignedMessage>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut signed_messages = Vec::with_capacity(keystores_paths.len());

    for path in keystores_paths {
        let kp = Keystore::from_json_file(path.clone()).map_err(KeystoreError::Eth2Keystore)?;
        let kp = kp.decrypt_keypair(password.as_bytes()).map_err(KeystoreError::Eth2Keystore)?;
        let validator_pubkey = BlsPublicKey::try_from(kp.pk.to_string().as_ref())?;
        let validator_private_key = kp.sk;

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), chain)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signature = BlsSignature::try_from(signature.serialize().as_ref())?;
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed));
            }
            Action::Revoke => {
                let message = RevocationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), chain)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signature = BlsSignature::try_from(signature.serialize().as_ref())?;
                let signed = SignedRevocation { message, signature };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }
    }

    Ok(signed_messages)
}

/// Write the signed delegation to an output json file
fn write_to_file<T: Serialize>(out: &str, messages: &Vec<T>) -> Result<()> {
    let out_path = PathBuf::from(out);
    let out_file = fs::File::create(out_path)?;
    serde_json::to_writer_pretty(out_file, &messages)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use crate::{
        config::{Action, Chain}, generate_from_keystore, types::SignedMessage, utils::{
            parse_public_key, verify_commit_boost_root,
        }
    };

    /// The str path of the root of the project
    pub const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn test_delegation_keystore_signer() {
        
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
        let keystore_password = r#"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"#;
        // let keystore_public_key = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
        // let keystore_public_key_bytes: [u8; 48] = [
        //     0x96, 0x12, 0xd7, 0xa7, 0x27, 0xc9, 0xd0, 0xa2, 0x2e, 0x18, 0x5a, 0x1c, 0x76, 0x84,
        //     0x78, 0xdf, 0xe9, 0x19, 0xca, 0xda, 0x92, 0x66, 0x98, 0x8c, 0xb3, 0x23, 0x59, 0xc1,
        //     0x1f, 0x2b, 0x7b, 0x27, 0xf4, 0xae, 0x40, 0x40, 0x90, 0x23, 0x82, 0xae, 0x29, 0x10,
        //     0xc1, 0x5e, 0x2b, 0x42, 0x0d, 0x07,
        // ];
        // let keystore_secret_key =
        //     "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

        
        // 1. Create a temp directory with the keystore and create a signer from it
        // NOTE: "keys" directory should be present already
        let path_str = format!("{}/{}", CARGO_MANIFEST_DIR, "keys");

        for test_keystore_json in tests_keystore_json {
            let tmp_dir = tempfile::TempDir::with_prefix_in(
                "0xdeadbeefdeadbeefdeadbeefdeadbeef",
                path_str.clone(),
            )
            .expect("to create temp dir");

            // NOTE: it is sufficient to create a temp dir, then we can create a file as usual and
            // it will be dropped correctly
            let mut tmp_file = File::create_new(tmp_dir.path().join("voting-keystore.json"))
                .expect("to create new file");

            tmp_file.write_all(test_keystore_json.as_bytes()).expect("to write to temp file");

            for entry in tmp_dir.path().read_dir().expect("to read tmp dir") {
                let mut path = entry.expect("to read entry").path();
                println!("inside loop: {:?}", path);
                let extenstion = path
                    .extension()
                    .expect("to get extension")
                    .to_str()
                    .expect("to convert to str");

                if extenstion.contains("tmp") {
                    path.set_extension("json");
                    println!("path: {:?}", path);
                    break;
                }
            }

            let delegatee_pubkey = "0x83eeddfac5e60f8fe607ee8713efb8877c295ad9f8ca075f4d8f6f2ae241a30dd57f78f6f3863a9fe0d5b5db9d550b93";
            let delegatee_pubkey = parse_public_key(delegatee_pubkey).expect("delegatee pubkey");

            let signed_delegations = generate_from_keystore(&path_str, &keystore_password, delegatee_pubkey.clone(), &Chain::Mainnet, Action::Delegate)
                        .expect("signed delegations");
            let signed_message = signed_delegations.first().expect("to get signed delegation");
            match signed_message {
                SignedMessage::Delegation(signed_delegation) => {
                    let output_delegatee_pubkey = signed_delegation.message.delegatee_pubkey.clone();
                    let signer_pubkey = signed_delegation.message.validator_pubkey.clone();
                    let digest = signed_delegation.message.digest();
                    assert_eq!(output_delegatee_pubkey, delegatee_pubkey);

                    let blst_sig = blst::min_pk::Signature::from_bytes(&signed_delegation.signature.as_ref())
                        .expect("Failed to convert delegation signature");

                    // Verify the signature
                    assert!(verify_commit_boost_root(signer_pubkey, digest, &blst_sig).is_ok());
                }
                _ => panic!("Expected a delegation message"),
                
            }
        }
    }
}
