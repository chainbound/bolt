use clap::{Parser, Subcommand, ValueEnum};

use crate::utils::KEYSTORE_PASSWORD;

/// A CLI tool to generate signed delegation messages for BLS keys.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Generate delegation messages.
    GenerateLocal {
        /// The private key in hex format (required if source is local).
        /// Multiple secret keys must be seperated by commas.
        #[clap(
            long,
            env = "SECRET_KEYS",
            value_parser,
            value_delimiter = ',',
            hide_env_values = true,
            conflicts_with("keystore_path")
        )]
        secret_key: Option<Vec<String>>,

        /// The BLS public key to which the delegation message should be signed.
        #[clap(long, env = "DELEGATEE_PUBKEY")]
        delegatee_pubkey: String,

        /// The output file for the delegations.
        #[clap(long, env = "OUTPUT_FILE_PATH", default_value = "delegations.json")]
        out: String,

        /// The chain for which the delegation message is intended.
        #[clap(long, env = "CHAIN", default_value = "mainnet")]
        chain: Chain,
    },

    GenerateKeystore {
        /// Path to the keystore file (required if source is keystore).
        #[clap(long, env = "KEY_PATH", conflicts_with("secret_key"))]
        keystore_path: Option<String>,

        /// The password for the keystore files in the path.
        /// Assumes all keystore files have the same password.
        #[clap(
            long,
            env = "KEYSTORE_PASSWORD",
            hide_env_values = true,
            conflicts_with("secret_key"),
            default_value = KEYSTORE_PASSWORD
        )]
        keystore_password: String,

        /// The BLS public key to which the delegation message should be signed.
        #[clap(long, env = "DELEGATEE_PUBKEY")]
        delegatee_pubkey: String,

        /// The output file for the delegations.
        #[clap(long, env = "OUTPUT_FILE_PATH", default_value = "delegations.json")]
        out: String,

        /// The chain for which the delegation message is intended.
        #[clap(long, env = "CHAIN", default_value = "mainnet")]
        chain: Chain,
    },
}

/// Supported chains for the CLI
#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab_case")]
pub enum Chain {
    Mainnet,
    Holesky,
    Helder,
    Kurtosis,
}

impl Chain {
    /// Get the fork version for the given chain.
    pub fn fork_version(&self) -> [u8; 4] {
        match self {
            Chain::Mainnet => [0, 0, 0, 0],
            Chain::Holesky => [1, 1, 112, 0],
            Chain::Helder => [16, 0, 0, 0],
            Chain::Kurtosis => [16, 0, 0, 56],
        }
    }
}
