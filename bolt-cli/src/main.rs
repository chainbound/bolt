use std::{fs, path::PathBuf};

use clap::Parser;
use eyre::{bail, Result};
use serde::Serialize;

mod config;
use config::{Commands, KeySource, Opts};

mod delegation;
use delegation::{generate_from_keystore, generate_from_local_keys};
use utils::{keystore::KeystoreSecret, parse_public_key};

mod types;

mod utils;

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
            KeySource::Keystore { path, password, password_path } => {
                let passwords = if let Some(password_path) = password_path {
                    KeystoreSecret::from_directory(password_path)?
                } else if let Some(password) = password {
                    KeystoreSecret::from_unique_password(password)
                } else {
                    bail!("Either `password_path` or `password` must be provided")
                };

                let delegatee = parse_public_key(&delegatee_pubkey)?;
                let messages = generate_from_keystore(&path, passwords, delegatee, chain, action)?;

                write_to_file(&out, &messages)?;
                println!("Signed delegation messages generated and saved to {}", out);
            }
        },
    }
    Ok(())
}

/// Write some serializable data to an output json file
fn write_to_file<T: Serialize>(out: &str, data: &T) -> Result<()> {
    let out_path = PathBuf::from(out);
    let out_file = fs::File::create(out_path)?;
    serde_json::to_writer_pretty(out_file, data)?;
    Ok(())
}
