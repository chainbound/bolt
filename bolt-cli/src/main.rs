use clap::Parser;
use eyre::Result;

/// CLI commands and options.
mod cli;
use cli::{Commands, KeySource, Opts};

/// Module for generating delegation/revocation messages for BLS keys.
mod delegation;

/// Module for listing BLS pubkeys from various sources.
mod pubkeys;

/// Utility functions and helpers for the CLI.
mod utils;
use tracing::debug;
use utils::{dirk::Dirk, keystore::KeystoreSecret, parse_bls_public_key, write_to_file};

/// Protocol Buffers definitions generated by `prost`.
mod pb;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    let _ = tracing_subscriber::fmt::try_init();

    let cli = Opts::parse();

    // Init the default rustls provider for Dirk
    let _ = rustls::crypto::ring::default_provider().install_default();

    match cli.command {
        Commands::Delegate { delegatee_pubkey, out, chain, source, action } => match source {
            KeySource::SecretKeys { secret_keys } => {
                let delegatee_pubkey = parse_bls_public_key(&delegatee_pubkey)?;
                let signed_messages = delegation::generate_from_local_keys(
                    &secret_keys,
                    delegatee_pubkey,
                    &chain,
                    action,
                )?;

                // Verify signatures
                for message in &signed_messages {
                    delegation::verify_message_signature(message, chain)?;
                }

                write_to_file(&out, &signed_messages)?;
                println!("Signed delegation messages generated and saved to {}", out);
            }
            KeySource::LocalKeystore { opts } => {
                let keystore_secret = KeystoreSecret::from_keystore_options(&opts)?;
                let delegatee_pubkey = parse_bls_public_key(&delegatee_pubkey)?;
                let signed_messages = delegation::generate_from_keystore(
                    &opts.path,
                    keystore_secret,
                    delegatee_pubkey,
                    chain,
                    action,
                )?;

                // Verify signatures
                for message in &signed_messages {
                    delegation::verify_message_signature(message, chain)?;
                }

                write_to_file(&out, &signed_messages)?;
                println!("Signed delegation messages generated and saved to {}", out);
            }
            KeySource::Dirk { opts } => {
                let mut dirk = Dirk::connect(opts.url, opts.tls_credentials).await?;
                let delegatee_pubkey = parse_bls_public_key(&delegatee_pubkey)?;

                let signed_messages = delegation::generate_from_dirk(
                    &mut dirk,
                    delegatee_pubkey,
                    opts.wallet_path,
                    opts.passphrases,
                    chain,
                    action,
                )
                .await?;
                debug!("Signed {} messages with Dirk", signed_messages.len());

                // Verify signatures
                for message in &signed_messages {
                    delegation::verify_message_signature(message, chain)?;
                }

                write_to_file(&out, &signed_messages)?;
                println!("Signed delegation messages generated and saved to {}", out);
            }
        },

        Commands::Pubkeys { source, out } => match source {
            KeySource::SecretKeys { secret_keys } => {
                let pubkeys = pubkeys::list_from_local_keys(&secret_keys)?;

                write_to_file(&out, &pubkeys)?;
                println!("Pubkeys generated and saved to {}", out);
            }
            KeySource::LocalKeystore { opts } => {
                let keystore_secret = KeystoreSecret::from_keystore_options(&opts)?;
                let pubkeys = pubkeys::list_from_keystore(&opts.path, keystore_secret)?;

                write_to_file(&out, &pubkeys)?;
                println!("Pubkeys generated and saved to {}", out);
            }
            KeySource::Dirk { opts } => {
                // Note: we don't need to unlock wallets to list pubkeys
                let mut dirk = Dirk::connect(opts.url, opts.tls_credentials).await?;
                let accounts = dirk.list_accounts(opts.wallet_path).await?;
                let pubkeys = pubkeys::list_from_dirk_accounts(&accounts)?;

                write_to_file(&out, &pubkeys)?;
                println!("Pubkeys generated and saved to {}", out);
            }
        },
    }

    Ok(())
}
