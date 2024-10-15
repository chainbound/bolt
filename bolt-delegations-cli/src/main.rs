use std::{fs, path::PathBuf};

use clap::Parser;
use ethereum_consensus::crypto::{PublicKey as BlsPublicKey, SecretKey, Signature as BlsSignature};
use eyre::Result;
use lighthouse_eth2_keystore::Keystore;

use bolt_delegations_cli::{
    config::{Commands, Opts, SourceType},
    types::{DelegationMessage, SignedDelegation},
    utils::{compute_signing_root_for_delegation, parse_public_key, KEYSTORE_PASSWORD},
};

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("Failed to read keystore directory: {0}")]
    ReadFromDirectory(#[from] std::io::Error),
    #[error("Failed to read keystore from JSON file {0}: {1}")]
    ReadFromJSON(String, String),
    #[error("Failed to decrypt keypair from JSON file {0} with the provided password: {1}")]
    KeypairDecryption(String, String),
    #[error("Could not find private key associated with public key {0}")]
    UnknownPublicKey(String),
    #[error("Invalid signature key length. Signature: {0}. Message: {1}")]
    SignatureLength(String, String),
}

fn main() -> Result<()> {
    let cli = Opts::parse();

    match &cli.command {
        Commands::Generate {
            source,
            key_path,
            delegatee_pubkey,
            out,
        } => {
            generate_delegations(source, key_path, delegatee_pubkey, out)?;
        }
    }

    Ok(())
}

/// Generate a signed delegation from a provided source
fn generate_delegations(
    source: &SourceType,
    key_path: &str,
    delegatee_pubkey: &str,
    out: &str,
) -> Result<()> {
    let delegatee_pubkey = parse_public_key(delegatee_pubkey)?;
    let signed_delegation = match source {
        SourceType::Local => generate_from_local_key(key_path, delegatee_pubkey)?,
        SourceType::Keystore => generate_from_keystore(key_path, delegatee_pubkey)?,
    };

    write_delegation_to_file(out, &signed_delegation)?;
    println!("Delegation message generated and saved to {}", out);
    Ok(())
}

/// Generate a signed delegation using a local BLS private key
fn generate_from_local_key(
    key_path: &str,
    delegatee_pubkey: BlsPublicKey,
) -> Result<SignedDelegation> {
    let sk_hex = fs::read_to_string(key_path)?;
    let sk = SecretKey::try_from(sk_hex)?;
    let delegation = DelegationMessage::new(sk.public_key(), delegatee_pubkey);

    let signing_root = compute_signing_root_for_delegation(&delegation)?;
    let sig = sk.sign(signing_root.0.as_ref());

    Ok(SignedDelegation {
        message: delegation,
        signature: sig,
    })
}

/// Generate a signed delegation using a keystore file
fn generate_from_keystore(
    key_path: &str,
    delegatee_pubkey: BlsPublicKey,
) -> Result<SignedDelegation> {
    let keypair = Keystore::from_json_file(key_path)
        .map_err(|e| KeystoreError::ReadFromJSON(key_path.to_owned(), format!("{e:?}")))?
        .decrypt_keypair(KEYSTORE_PASSWORD.as_bytes())
        .map_err(|e| KeystoreError::KeypairDecryption(key_path.to_owned(), format!("{e:?}")))?;

    let delegation = DelegationMessage::new(
        BlsPublicKey::try_from(keypair.pk.to_string().as_ref())?,
        delegatee_pubkey,
    );

    let signing_root = compute_signing_root_for_delegation(&delegation)?;
    let sig = keypair.sk.sign(signing_root.0.into());

    Ok(SignedDelegation {
        message: delegation,
        signature: BlsSignature::try_from(sig.serialize().as_ref())?,
    })
}

/// Write the signed delegation to an output file
fn write_delegation_to_file(out: &str, signed_delegation: &SignedDelegation) -> Result<()> {
    let out_path = PathBuf::from(out);
    let out_file = fs::File::create(out_path)?;
    serde_json::to_writer_pretty(out_file, &signed_delegation)?;
    Ok(())
}
