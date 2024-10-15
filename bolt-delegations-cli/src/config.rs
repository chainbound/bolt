use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;

use crate::utils::KEYSTORE_PASSWORD;

/// A CLI tool to generate signed delegation messages for BLS keys.
#[derive(Parser, Debug, Clone, Deserialize)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// The subcommand to run.
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone, Deserialize)]
pub enum Commands {
    /// Generate delegation messages.
    Generate {
        /// The BLS public key to which the delegation message should be signed.
        #[clap(long, env = "DELEGATEE_PUBKEY")]
        delegatee_pubkey: String,

        /// The output file for the delegations.
        #[clap(long, env = "OUTPUT_FILE_PATH", default_value = "delegations.json")]
        out: String,

        /// The chain for which the delegation message is intended.
        #[clap(long, env = "CHAIN", default_value = "mainnet")]
        chain: Chain,

        /// The source of the private key.
        #[clap(subcommand)]
        source: KeySource,

        /// The action to perform. The tool can be used to generate
        /// delegation or revocation messages (default: delegate).
        #[clap(long, default_value = "delegate")]
        action: Action,
    },
}

#[derive(Debug, Clone, ValueEnum, Deserialize)]
pub enum Action {
    Delegate,
    Revoke,
}

#[derive(Debug, Clone, Parser, Deserialize)]
pub enum KeySource {
    Local {
        /// The private key in hex format (required if source is local).
        /// Multiple secret keys must be seperated by commas.
        #[clap(long, env = "SECRET_KEYS", value_delimiter = ',', hide_env_values = true)]
        secret_keys: Vec<String>,
    },
    Keystore {
        /// Path to the keystore file.
        #[clap(long, env = "KEYSTORE_PATH")]
        keystore_path: String,
        /// The password for the keystore files in the path.
        /// Assumes all keystore files have the same password.
        #[clap(
            long,
            env = "KEYSTORE_PASSWORD",
            hide_env_values = true,
            default_value = KEYSTORE_PASSWORD
        )]
        keystore_password: String,
    },
}

/// Supported chains for the CLI
#[derive(Debug, Clone, Copy, ValueEnum, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::Opts;

    #[test]
    pub fn verify_cli() {
        use clap::CommandFactory;
        Opts::command().debug_assert()
    }
}
