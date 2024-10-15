use std::{fs, path::PathBuf};

use clap::Parser;
use ethereum_consensus::crypto::{PublicKey as BlsPublicKey, SecretKey, Signature as BlsSignature};
use eyre::Result;
use lighthouse_eth2_keystore::Keystore;

use bolt_delegations_cli::{
    config::{Chain, Commands, Opts, SourceType},
    types::{DelegationMessage, KeystoreError, SignedDelegation},
    utils::{compute_signing_root_for_delegation, parse_public_key, KEYSTORE_PASSWORD},
};

fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    let cli = Opts::parse();

    match &cli.command {
        Commands::Generate { source, key_path, delegatee_pubkey, out, chain } => {
            let delegatee_pubkey = parse_public_key(delegatee_pubkey)?;
            let signed_delegation = match source {
                SourceType::Local => generate_from_local_key(key_path, delegatee_pubkey, chain)?,
                SourceType::Keystore => generate_from_keystore(key_path, delegatee_pubkey, chain)?,
            };

            write_delegation_to_file(out, &signed_delegation)?;
            println!("Delegation message generated and saved to {}", out);
        }
    }

    Ok(())
}

/// Generate a signed delegation using a local BLS private key
///
/// - Read the private key from the file
/// - Create a delegation message
/// - Compute the signing root and sign the message
/// - Return the signed delegation
fn generate_from_local_key(
    key_path: &str,
    delegatee_pubkey: BlsPublicKey,
    chain: &Chain,
) -> Result<SignedDelegation> {
    let sk_hex = fs::read_to_string(key_path)?;
    let sk = SecretKey::try_from(sk_hex)?;
    let delegation = DelegationMessage::new(sk.public_key(), delegatee_pubkey);

    let signing_root = compute_signing_root_for_delegation(&delegation, chain)?;
    let sig = sk.sign(signing_root.0.as_ref());

    Ok(SignedDelegation { message: delegation, signature: sig })
}

/// Generate a signed delegation using a keystore file
///
/// - Read the keystore file
/// - Decrypt the keypair using the default password (TODO: make this configurable)
/// - Create a delegation message
/// - Compute the signing root and sign the message
/// - Return the signed delegation
fn generate_from_keystore(
    key_path: &str,
    delegatee_pubkey: BlsPublicKey,
    chain: &Chain,
) -> Result<SignedDelegation> {
    let keypair = Keystore::from_json_file(key_path)
        .map_err(|e| KeystoreError::ReadFromJSON(key_path.to_string(), format!("{e:?}")))?
        .decrypt_keypair(KEYSTORE_PASSWORD.as_bytes())
        .map_err(|e| KeystoreError::KeypairDecryption(key_path.to_string(), format!("{e:?}")))?;

    let delegation = DelegationMessage::new(
        BlsPublicKey::try_from(keypair.pk.to_string().as_ref())
            .map_err(|e| KeystoreError::UnknownPublicKey(format!("{e:?}")))?,
        delegatee_pubkey,
    );

    let signing_root = compute_signing_root_for_delegation(&delegation, chain)?;
    let sig = keypair.sk.sign(signing_root.0.into());

    Ok(SignedDelegation {
        message: delegation,
        signature: BlsSignature::try_from(sig.serialize().as_ref())?,
    })
}

/// Write the signed delegation to an output json file
fn write_delegation_to_file(out: &str, signed_delegation: &SignedDelegation) -> Result<()> {
    let out_path = PathBuf::from(out);
    let out_file = fs::File::create(out_path)?;
    serde_json::to_writer_pretty(out_file, &signed_delegation)?;
    Ok(())
}
