use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;

use crate::utils::keystore::DEFAULT_KEYSTORE_PASSWORD;

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
    /// Generate BLS delegation or revocation messages.
    Delegate {
        /// The BLS public key to which the delegation message should be signed.
        #[clap(long, env = "DELEGATEE_PUBKEY")]
        delegatee_pubkey: String,

        /// The output file for the delegations.
        #[clap(long, env = "OUTPUT_FILE_PATH", default_value = "delegations.json")]
        out: String,

        /// The chain for which the delegation message is intended.
        #[clap(long, env = "CHAIN", default_value = "mainnet")]
        chain: Chain,

        /// The action to perform. The tool can be used to generate
        /// delegation or revocation messages (default: delegate).
        #[clap(long, env = "ACTION", default_value = "delegate")]
        action: Action,

        /// The source of the private key.
        #[clap(subcommand)]
        source: KeySource,
    },

    /// Output a list of pubkeys in JSON format.
    Pubkeys {
        /// The output file for the pubkeys.
        #[clap(long, env = "OUTPUT_FILE_PATH", default_value = "pubkeys.json")]
        out: String,

        /// The source of the private keys from which to extract the pubkeys.
        #[clap(subcommand)]
        source: KeySource,
    },
}

/// The action to perform.
#[derive(Debug, Clone, ValueEnum, Deserialize)]
pub enum Action {
    /// Create a delegation message.
    Delegate,
    /// Create a revocation message.
    Revoke,
}

#[derive(Debug, Clone, Parser, Deserialize)]
pub enum KeySource {
    /// Use local secret keys to generate the signed messages.
    SecretKeys {
        /// The private key in hex format.
        /// Multiple secret keys must be seperated by commas.
        #[clap(long, env = "SECRET_KEYS", value_delimiter = ',', hide_env_values = true)]
        secret_keys: Vec<String>,
    },

    /// Use an EIP-2335 filesystem keystore directory to generate the signed messages.
    LocalKeystore {
        /// The options for reading the keystore directory.
        #[clap(flatten)]
        opts: LocalKeystoreOpts,
    },

    /// Use a remote DIRK keystore to generate the signed messages.
    Dirk {
        /// The options for connecting to the DIRK keystore.
        #[clap(flatten)]
        opts: DirkOpts,
    },
}

/// Options for reading a keystore folder.
#[derive(Debug, Clone, Deserialize, Parser)]
pub struct LocalKeystoreOpts {
    /// The path to the keystore file.
    #[clap(long, env = "KEYSTORE_PATH", default_value = "validators")]
    pub path: String,

    /// The password for the keystore files in the path.
    /// Assumes all keystore files have the same password.
    #[clap(
        long,
        env = "KEYSTORE_PASSWORD",
        hide_env_values = true,
        default_value = DEFAULT_KEYSTORE_PASSWORD,
        conflicts_with = "password_path"
    )]
    pub password: Option<String>,

    #[clap(
        long,
        env = "KEYSTORE_PASSWORD_PATH",
        default_value = "secrets",
        conflicts_with = "password"
    )]
    pub password_path: Option<String>,
}

/// Options for connecting to a DIRK keystore.
#[derive(Debug, Clone, Deserialize, Parser)]
pub struct DirkOpts {
    /// The URL of the DIRK keystore.
    #[clap(long, env = "DIRK_URL")]
    pub url: String,

    /// The TLS credentials for connecting to the DIRK keystore.
    #[clap(flatten)]
    pub tls_credentials: TlsCredentials,

    /// The paths to the accounts in the DIRK keystore.
    #[clap(long, env = "DIRK_ACCOUNTS", value_delimiter = ',', hide_env_values = true)]
    pub accounts: Vec<String>,
}

/// TLS credentials for connecting to a remote server.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Parser)]
pub struct TlsCredentials {
    /// Path to the client certificate file. (.crt)
    #[clap(long, env = "CLIENT_CERT_PATH")]
    pub client_cert_path: String,
    /// Path to the client key file. (.key)
    #[clap(long, env = "CLIENT_KEY_PATH")]
    pub client_key_path: String,
    /// Path to the CA certificate file. (.crt)
    #[clap(long, env = "CA_CERT_PATH")]
    pub ca_cert_path: Option<String>,
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
