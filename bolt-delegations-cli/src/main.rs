use alloy::primitives::FixedBytes;
// use alloy::signers::k256::SecretKey;
use bolt_delegations_cli::utils::compute_domain_from_mask;
use clap::Parser;
use ethereum_consensus::crypto::{PublicKey as BlsPublicKey, SecretKey, Signature as BlsSignature};
use ethereum_consensus::deneb::compute_signing_root;
use eyre::Result;
use lighthouse_eth2_keystore::Keystore;
use serde::Serialize;
use std::hash::Hash;
use std::path::PathBuf;
use std::{fs, str::FromStr};

// Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
const KEYSTORE_PASSWORD: &str = r#"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"#;
pub const COMMIT_BOOST_DOMAIN_MASK: [u8; 4] = [109, 109, 111, 67];

// mod keystore_signer;
// use keystore_signer::KeystoreSigner;
use bolt_delegations_cli::{
    config::{Commands, Opts, SourceType},
    types::{DelegationMessage, SignedDelegation},
};

fn main() -> Result<()> {
    let cli = Opts::parse();

    match &cli.command {
        Commands::Generate {
            source,
            key_path,
            delegated_key,
            out,
        } => {
            generate_delegations(source, key_path, delegated_key, out)?;
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("Failed to read keystore directory: {0}")]
    ReadFromDirectory(#[from] std::io::Error),
    #[error("Failed to read keystore from JSON file {0}: {1}")]
    ReadFromJSON(String, String),
    #[error("Failed to decrypt keypair from JSON file {0} with the provided password: {1}")]
    KeypairDecryption(String, String),
    #[error("Could not find private key associated to public key {0}")]
    UnknownPublicKey(String),
    #[error("Invalid signature key length. Signature: {0}. Message: {1}")]
    SignatureLength(String, String),
}

fn generate_delegations(
    source: &SourceType,
    key_path: &str,
    delegated_key: &str,
    out: &str,
) -> Result<()> {
    // Parse the delegated public key
    let delegated_pubkey = BlsPublicKey::try_from(delegated_key.as_ref())?;

    // Depending on the source, load the secret key
    let signed_delegation: SignedDelegation = match source {
        SourceType::Local => {
            // Read the BLS private key from the file
            let sk_hex = fs::read_to_string(key_path)?;
            let sk = SecretKey::try_from(sk_hex).unwrap();
            let delegation = DelegationMessage::new(sk.public_key(), delegated_pubkey);
            let message = delegation.digest();
            let signing_root =
                compute_signing_root(&message, compute_domain_from_mask(COMMIT_BOOST_DOMAIN_MASK))?;

            let sig = sk.sign(signing_root.0.as_ref());

            SignedDelegation {
                message: delegation,
                signature: sig,
            }
        }
        SourceType::Keystore => {
            let keypair = Keystore::from_json_file(key_path);
            let keypair = keypair
                .map_err(|e| KeystoreError::ReadFromJSON(key_path.to_owned(), format!("{e:?}")))?
                .decrypt_keypair(KEYSTORE_PASSWORD.as_bytes())
                .map_err(|e| {
                    KeystoreError::KeypairDecryption(key_path.to_owned(), format!("{e:?}"))
                })?;

            let delegation = DelegationMessage::new(
                BlsPublicKey::try_from(keypair.pk.to_string().as_ref())?,
                delegated_pubkey,
            );
            let message = delegation.digest();
            let signing_root =
                compute_signing_root(&message, compute_domain_from_mask(COMMIT_BOOST_DOMAIN_MASK))?;

            // let signing_root_h256 =  ::from_slice(signing_root.as_slice());
            let sig = keypair.sk.sign(signing_root.0.into());
            SignedDelegation {
                message: delegation,
                signature: BlsSignature::try_from(sig.serialize().as_ref())?,
            }
        }
    };

    // Write to the output file
    let out_path = PathBuf::from(out);
    let out_file = fs::File::create(out_path)?;
    serde_json::to_writer_pretty(out_file, &signed_delegation)?;

    println!("Delegation message generated and saved to {}", out);

    Ok(())
}
