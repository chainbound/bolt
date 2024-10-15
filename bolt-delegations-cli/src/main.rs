use std::{fs, path::PathBuf};

use clap::Parser;
use ethereum_consensus::crypto::{PublicKey as BlsPublicKey, SecretKey, Signature as BlsSignature};
use eyre::Result;
use lighthouse_eth2_keystore::Keystore;

pub mod config;
use config::{Chain, Commands, Opts};

pub mod types;
use types::{DelegationMessage, KeystoreError, SignedDelegation};

pub mod utils;
use utils::{compute_signing_root_for_delegation, keystore_paths, parse_public_key};

fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    let cli = Opts::parse();

    match &cli.command {
        Commands::GenerateLocal { secret_keys, delegatee_pubkey, out, chain } => {
            let secret_keys = secret_keys.as_ref().unwrap();
            let delegatee_pubkey = parse_public_key(delegatee_pubkey)?;
            let signed_delegation = generate_from_local_key(secret_keys, delegatee_pubkey, chain)?;

            write_delegations_to_file(out, &signed_delegation)?;
            println!("Signed delegation messages generated and saved to {}", out);
        }
        Commands::GenerateKeystore {
            keystore_path,
            keystore_password,
            delegatee_pubkey,
            out,
            chain,
        } => {
            let delegatee_pubkey = parse_public_key(delegatee_pubkey)?;
            let signed_delegation = generate_from_keystore(
                keystore_path.as_deref(),
                keystore_password.as_bytes(),
                delegatee_pubkey,
                chain,
            )?;

            write_delegations_to_file(out, &signed_delegation)?;
            println!("Signed delegation messages generated and saved to {}", out);
        }
    }

    Ok(())
}

/// Generate a signed delegation using a local BLS private key
///
/// - Use the provided private key from either CLI or env variable
/// - Create a delegation message
/// - Compute the signing root and sign the message
/// - Return the signed delegation
fn generate_from_local_key(
    secret_keys: &Vec<String>,
    delegatee_pubkey: BlsPublicKey,
    chain: &Chain,
) -> Result<Vec<SignedDelegation>> {
    let mut signed_delegations = Vec::with_capacity(secret_keys.len());

    for sk in secret_keys {
        let sk = SecretKey::try_from(sk.trim().to_string())?;
        let delegation = DelegationMessage::new(sk.public_key(), delegatee_pubkey.clone());

        let signing_root = compute_signing_root_for_delegation(&delegation, chain)?;
        let sig = sk.sign(signing_root.0.as_ref());

        signed_delegations.push(SignedDelegation {
            message: delegation,
            signature: BlsSignature::try_from(sig)?,
        });
    }

    Ok(signed_delegations)
}

/// Generate a signed delegation using a keystore file
///
/// - Read the keystore file
/// - Decrypt the keypair using the password
/// - Create a delegation message
/// - Compute the signing root and sign the message
/// - Return the signed delegation
fn generate_from_keystore(
    keys_path: Option<&str>,
    password: &[u8],
    delegatee_pubkey: BlsPublicKey,
    chain: &Chain,
) -> Result<Vec<SignedDelegation>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut signed_delegations = Vec::with_capacity(keystores_paths.len());

    for path in keystores_paths {
        let keypair = Keystore::from_json_file(path.clone());
        let keypair = keypair
            .map_err(|e| KeystoreError::ReadFromJSON(path.clone(), format!("{e:?}")))?
            .decrypt_keypair(password)
            .map_err(|e| KeystoreError::KeypairDecryption(path.clone(), format!("{e:?}")))?;

        let delegation = DelegationMessage::new(
            BlsPublicKey::try_from(keypair.pk.to_string().as_ref())
                .map_err(|e| KeystoreError::UnknownPublicKey(format!("{e:?}")))?,
            delegatee_pubkey.clone(),
        );
        let signing_root = compute_signing_root_for_delegation(&delegation, chain)?;
        let sig = keypair.sk.sign(signing_root.0.into());

        signed_delegations.push(SignedDelegation {
            message: delegation,
            signature: BlsSignature::try_from(sig.serialize().as_ref())?,
        });
    }

    Ok(signed_delegations)
}

/// Write the signed delegation to an output json file
fn write_delegations_to_file(out: &str, signed_delegations: &Vec<SignedDelegation>) -> Result<()> {
    let out_path = PathBuf::from(out);
    let out_file = fs::File::create(out_path)?;
    serde_json::to_writer_pretty(out_file, &signed_delegations)?;
    Ok(())
}
