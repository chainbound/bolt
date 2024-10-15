use clap::{Parser, Subcommand, ValueEnum};

/// A CLI tool to generate delegation messages for BLS keys.
#[derive(Parser, Debug, Clone)]
pub struct Opts {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Generate delegation messages.
    Generate {
        /// The source of the validator key (local or keystore).
        #[clap(short, long)]
        source: SourceType,

        /// Path to the keystore file or private key, depending on the source.
        #[clap(short, long)]
        key_path: String,

        /// The BLS public key to which the delegation message should be signed.
        #[clap(short, long)]
        delegatee_pubkey: String,

        /// The output file for the delegations.
        #[clap(long, default_value = "delegations.json")]
        out: String,
    },
}

#[derive(ValueEnum, Debug, Clone)]
pub enum SourceType {
    Local,
    Keystore,
}
