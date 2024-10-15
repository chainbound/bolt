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
