use clap::{Parser, Subcommand, ValueEnum};

/// A CLI tool to generate signed delegation messages for BLS keys.
#[derive(Parser, Debug, Clone)]
pub struct Opts {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Generate delegation messages.
    Generate {
        /// The source of the validator key (local or keystore).
        #[clap(long, env = "SOURCE")]
        source: SourceType,

        /// Path to the keystore file or private key, depending on the source.
        #[clap(long, env = "KEY_PATH")]
        key_path: String,

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

#[derive(ValueEnum, Debug, Clone)]
pub enum SourceType {
    Local,
    Keystore,
}

/// Supported chains for the cli
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
