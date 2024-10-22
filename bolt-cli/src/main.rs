use clap::Parser;
use eyre::{bail, Result};

mod cli;
use cli::{Commands, KeySource, Opts};

mod delegation;
use delegation::{generate_from_keystore, generate_from_local_keys};

mod utils;
use utils::{keystore::KeystoreSecret, parse_bls_public_key, write_to_file};

fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    let cli = Opts::parse();

    match cli.command {
        Commands::Delegate { delegatee_pubkey, out, chain, source, action } => match source {
            KeySource::Local { secret_keys } => {
                let delegatee = parse_bls_public_key(&delegatee_pubkey)?;
                let messages = generate_from_local_keys(&secret_keys, delegatee, &chain, action)?;

                write_to_file(&out, &messages)?;
                println!("Signed delegation messages generated and saved to {}", out);
            }
            KeySource::Keystore { path, password, password_path } => {
                let passwords = if let Some(password_path) = password_path {
                    KeystoreSecret::from_directory(password_path)?
                } else if let Some(password) = password {
                    KeystoreSecret::from_unique_password(password)
                } else {
                    // This case is prevented upstream by clap's validation.
                    bail!("Either `password_path` or `password` must be provided")
                };

                let delegatee = parse_bls_public_key(&delegatee_pubkey)?;
                let messages = generate_from_keystore(&path, passwords, delegatee, chain, action)?;

                write_to_file(&out, &messages)?;
                println!("Signed delegation messages generated and saved to {}", out);
            }
        },
    }
    Ok(())
}
