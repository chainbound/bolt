use std::path::PathBuf;

use alloy::{
    primitives::{Address, FixedBytes, B256, U256},
    providers::Provider,
    transports::Transport,
};
use clap::{
    builder::styling::{AnsiColor, Color, Style},
    Parser, Subcommand, ValueEnum,
};
use reqwest::Url;

use crate::{
    common::{keystore::DEFAULT_KEYSTORE_PASSWORD, parse_ether_value},
    contracts::EigenLayerStrategy,
};

/// `bolt` is a CLI tool to interact with bolt Protocol ✨
#[derive(Parser, Debug, Clone)]
#[command(author, version, styles = cli_styles(), about, arg_required_else_help(true))]
pub struct Opts {
    /// The subcommand to run.
    #[clap(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Cmd {
    /// Generate BLS delegation or revocation messages.
    Delegate(DelegateCommand),

    /// Output a list of pubkeys in JSON format.
    Pubkeys(PubkeysCommand),

    /// Send a preconfirmation request to a bolt proposer.
    Send(Box<SendCommand>),

    /// Handle validators in the bolt network.
    Validators(ValidatorsCommand),

    /// Handle operators in the bolt network.
    Operators(OperatorsCommand),

    /// Useful data generation commands.
    Generate(GenerateCommand),

    /// Output the pubkey hash of a BLS public key.
    #[clap(hide = true)]
    PubkeyHash(PubkeyHashCommand),
}

impl Cmd {
    /// Run the command.
    pub async fn run(self) -> eyre::Result<()> {
        match self {
            Self::Delegate(cmd) => cmd.run().await,
            Self::Pubkeys(cmd) => cmd.run().await,
            Self::Send(cmd) => cmd.run().await,
            Self::Validators(cmd) => cmd.run().await,
            Self::Operators(cmd) => cmd.run().await,
            Self::Generate(cmd) => cmd.run(),
            Self::PubkeyHash(cmd) => cmd.run(),
        }
    }
}

/// Command for generating BLS delegation or revocation messages.
#[derive(Debug, Clone, Parser)]
pub struct DelegateCommand {
    /// The BLS public key to which the delegation message should be signed.
    #[clap(long, env = "DELEGATEE_PUBKEY")]
    pub delegatee_pubkey: String,

    /// The output file for the delegations.
    #[clap(long, env = "OUTPUT_FILE_PATH", default_value = "delegations.json")]
    pub out: String,

    /// The chain for which the delegation message is intended.
    #[clap(long, env = "CHAIN")]
    pub chain: Chain,

    /// The action to perform. The tool can be used to generate
    /// delegation or revocation messages (default: delegate).
    #[clap(long, env = "ACTION", default_value = "delegate")]
    pub action: Action,

    /// The source of the private key.
    #[clap(subcommand)]
    pub source: KeysSource,
}

/// Command for outputting a list of pubkeys in JSON format.
#[derive(Debug, Clone, Parser)]
pub struct PubkeysCommand {
    /// The output file for the pubkeys.
    #[clap(long, env = "OUTPUT_FILE_PATH", default_value = "pubkeys.json")]
    pub out: String,

    /// The source of the private keys from which to extract the pubkeys.
    #[clap(subcommand)]
    pub source: KeysSource,
}

/// Command for sending a preconfirmation request to a bolt proposer.
#[derive(Debug, Clone, Parser)]
pub struct SendCommand {
    /// bolt RPC URL to send requests to and fetch lookahead info from.
    ///
    /// Leaving this empty will default to the canonical bolt RPC URL, which
    /// automatically manages increasing nonces on preconfirmed state.
    #[clap(long, env = "BOLT_RPC_URL", default_value = "https://rpc-holesky.bolt.chainbound.io")]
    pub bolt_rpc_url: Url,

    /// The private key to sign the transaction with.
    #[clap(long, env = "PRIVATE_KEY", hide_env_values = true)]
    pub private_key: String,

    /// The bolt Sidecar URL to send requests to. If provided, this will override
    /// the canonical bolt RPC URL and disregard any registration information.
    ///
    /// This is useful for testing and development purposes.
    #[clap(long, env = "OVERRIDE_BOLT_SIDECAR_URL")]
    pub override_bolt_sidecar_url: Option<Url>,

    /// How many transactions to send.
    #[clap(long, env = "TRANSACTION_COUNT", default_value = "1")]
    pub count: u32,

    /// If set, the transaction will be blob-carrying (type 3)
    #[clap(long, env = "BLOB", default_value = "false")]
    pub blob: bool,

    /// The max fee per gas in gwei.
    #[clap(long, env = "MAX_FEE")]
    pub max_fee: Option<u128>,

    /// The max priority fee per gas in gwei.
    #[clap(long, env = "PRIORITY_FEE", default_value = "2")]
    pub priority_fee: u128,

    /// If set, the transaction will target the devnet environment.
    /// This is only used in Kurtosis for internal testing purposes
    #[clap(long, hide = true, env = "DEVNET", default_value = "false")]
    pub devnet: bool,

    /// The URL of the devnet execution client for filling transactions
    #[clap(long = "devnet.execution_url", hide = true)]
    pub devnet_execution_url: Option<Url>,

    /// The URL of the devnet beacon node for fetching slot numbers
    #[clap(long = "devnet.beacon_url", hide = true)]
    pub devnet_beacon_url: Option<Url>,

    /// The URL of the devnet sidecar for sending transactions
    #[clap(long = "devnet.sidecar_url", hide = true)]
    pub devnet_sidecar_url: Option<Url>,
}

#[derive(Debug, Clone, Parser)]
pub struct ValidatorsCommand {
    #[clap(subcommand)]
    pub subcommand: ValidatorsSubcommand,
}

#[derive(Debug, Clone, Parser)]
pub enum ValidatorsSubcommand {
    /// Register a batch of validators.
    Register {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,

        /// The max gas limit the validator is willing to reserve to commitments.
        #[clap(long, env = "MAX_COMMITTED_GAS_LIMIT")]
        max_committed_gas_limit: u32,

        /// The authorized operator for the validator.
        #[clap(long, env = "AUTHORIZED_OPERATOR")]
        authorized_operator: Address,

        /// The path to the JSON pubkeys file, containing an array of BLS public keys.
        #[clap(long, env = "PUBKEYS_PATH", default_value = "pubkeys.json")]
        pubkeys_path: PathBuf,

        /// The private key to sign the transactions with.
        #[clap(long, env = "ADMIN_PRIVATE_KEY")]
        admin_private_key: B256,
    },
    /// Check the status of a validator (batch).
    Status {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,

        /// The path to the JSON pubkeys file, containing an array of BLS public keys.
        #[clap(long, env = "PUBKEYS_PATH", conflicts_with = "pubkeys")]
        pubkeys_path: Option<PathBuf>,

        /// The validator public key to check the status of.
        #[clap(long, env = "PUBKEYS", conflicts_with = "pubkeys_path")]
        pubkeys: Vec<FixedBytes<48>>,
    },
}

#[derive(Debug, Clone, Parser)]
pub struct OperatorsCommand {
    #[clap(subcommand)]
    pub subcommand: OperatorsSubcommand,
}

#[derive(Debug, Clone, Parser)]
pub enum OperatorsSubcommand {
    /// Commands to interact with EigenLayer and bolt.
    #[clap(name = "eigenlayer")] // and not eigen-layer
    EigenLayer {
        #[clap(subcommand)]
        subcommand: EigenLayerSubcommand,
    },
    /// Commands to interact with Symbiotic and bolt.
    Symbiotic {
        #[clap(subcommand)]
        subcommand: SymbioticSubcommand,
    },
}

#[derive(Debug, Clone, Parser)]
pub enum EigenLayerSubcommand {
    /// Deposit into a strategy.
    Deposit {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,
        /// The private key of the operator.
        #[clap(long, env = "OPERATOR_PRIVATE_KEY")]
        operator_private_key: B256,
        /// The name of the strategy to deposit into.
        #[clap(long, env = "EIGENLAYER_STRATEGY")]
        strategy: EigenLayerStrategy,
        /// The amount to deposit into the strategy, in units (e.g. '1ether', '10gwei')
        /// If no unit is provided, it is assumed to be in wei.
        #[clap(long, env = "EIGENLAYER_STRATEGY_DEPOSIT_AMOUNT", value_parser = parse_ether_value)]
        amount: U256,
    },

    /// Register an operator into the bolt AVS.
    Register {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,
        /// The private key of the operator.
        #[clap(long, env = "OPERATOR_PRIVATE_KEY")]
        operator_private_key: B256,
        /// The URL of the operator RPC.
        #[clap(long, env = "OPERATOR_RPC")]
        operator_rpc: Url,
        /// The salt for the operator signature.
        #[clap(long, env = "OPERATOR_SIGNATURE_SALT")]
        salt: B256,
    },

    /// Deregister an EigenLayer operator from the bolt AVS.
    Deregister {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,
        /// The private key of the operator.
        #[clap(long, env = "OPERATOR_PRIVATE_KEY")]
        operator_private_key: B256,
    },

    /// Update the operator RPC.
    UpdateRpc {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,
        /// The private key of the operator.
        #[clap(long, env = "OPERATOR_PRIVATE_KEY")]
        operator_private_key: B256,
        /// The URL of the operator RPC.
        #[clap(long, env = "OPERATOR_RPC")]
        operator_rpc: Url,
    },

    /// Check the status of an operator in the bolt AVS.
    Status {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,
        /// The address of the operator to check.
        #[clap(long, env = "OPERATOR_ADDRESS")]
        address: Address,
    },
}

#[derive(Debug, Clone, Parser)]
pub enum SymbioticSubcommand {
    /// Register into the bolt manager contract as a Symbiotic operator.
    Register {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,
        /// The private key of the operator.
        #[clap(long, env = "OPERATOR_PRIVATE_KEY")]
        operator_private_key: B256,
        /// The URL of the operator RPC.
        #[clap(long, env = "OPERATOR_RPC")]
        operator_rpc: Url,
    },

    /// Deregister a Symbiotic operator from bolt.
    Deregister {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,
        /// The private key of the operator.
        #[clap(long, env = "OPERATOR_PRIVATE_KEY")]
        operator_private_key: B256,
    },

    /// Update the operator RPC.
    UpdateRpc {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,
        /// The private key of the operator.
        #[clap(long, env = "OPERATOR_PRIVATE_KEY")]
        operator_private_key: B256,
        /// The URL of the operator RPC.
        #[clap(long, env = "OPERATOR_RPC")]
        operator_rpc: Url,
    },

    /// Check the status of a Symbiotic operator.
    Status {
        /// The URL of the RPC to broadcast the transaction.
        #[clap(long, env = "RPC_URL")]
        rpc_url: Url,
        /// The address of the operator to check.
        #[clap(long, env = "OPERATOR_ADDRESS")]
        address: Address,
    },
}

#[derive(Debug, Clone, Parser)]
pub struct GenerateCommand {
    #[clap(subcommand)]
    pub generate: GenerateSubcommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum GenerateSubcommand {
    /// Generate a BLS keypair.
    Bls,
}

#[derive(Debug, Clone, Parser)]
pub struct PubkeyHashCommand {
    /// The BLS public key to hash.
    #[clap(value_parser, env = "KEY")]
    pub key: String,
}

/// The action to perform.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab_case")]
pub enum Action {
    /// Create a delegation message.
    Delegate,
    /// Create a revocation message.
    Revoke,
}

#[derive(Debug, Clone, Parser)]
pub enum KeysSource {
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

    /// Use a remote Web3Signer keystore to generate the signed messages.
    #[clap(name = "web3signer")]
    Web3Signer {
        #[clap(flatten)]
        opts: Web3SignerOpts,
    },
}

/// Options for reading a keystore folder.
#[derive(Debug, Clone, Parser)]
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
#[derive(Debug, Clone, Parser)]
pub struct DirkOpts {
    /// The URL of the DIRK keystore.
    #[clap(long, env = "DIRK_URL")]
    pub url: String,

    /// The path of the wallets in the DIRK keystore.
    #[clap(long, env = "DIRK_WALLET_PATH")]
    pub wallet_path: String,

    /// The passphrases to unlock the wallet in the DIRK keystore.
    /// If multiple are provided, they are tried in order until one works.
    #[clap(long, env = "DIRK_PASSPHRASES", value_delimiter = ',', hide_env_values = true)]
    pub passphrases: Option<Vec<String>>,

    /// The TLS credentials for connecting to the DIRK keystore.
    #[clap(flatten)]
    pub tls_credentials: DirkTlsCredentials,
}

/// Options for connecting to a Web3Signer keystore.
#[derive(Debug, Clone, Parser)]
pub struct Web3SignerOpts {
    /// The URL of the Web3Signer keystore.
    #[clap(long, env = "WEB3SIGNER_URL")]
    pub url: String,

    /// The TLS credentials for connecting to the Web3Signer keystore.
    #[clap(flatten)]
    pub tls_credentials: Web3SignerTlsCredentials,
}

/// TLS credentials for connecting to a remote Web3Signer server.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct Web3SignerTlsCredentials {
    /// Path to the CA certificate file. (.crt)
    #[clap(long, env = "CA_CERT_PATH")]
    pub ca_cert_path: String,
    /// Path to the PEM encoded private key and certificate file. (.pem)
    #[clap(long, env = "CLIENT_COMBINED_PEM_PATH")]
    pub combined_pem_path: String,
}

/// TLS credentials for connecting to a remote Dirk server.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub struct DirkTlsCredentials {
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
#[derive(Debug, Clone, Copy, ValueEnum, Hash, PartialEq, Eq)]
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
            Self::Mainnet => [0, 0, 0, 0],
            Self::Holesky => [1, 1, 112, 0],
            Self::Helder => [16, 0, 0, 0],
            Self::Kurtosis => [16, 0, 0, 56],
        }
    }

    /// Get the chain ID for the given chain. Returns `None` if the chain ID is not supported.
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            1 => Some(Self::Mainnet),
            17000 => Some(Self::Holesky),
            3151908 => Some(Self::Kurtosis),
            7014190335 => Some(Self::Helder),
            _ => None,
        }
    }

    /// Get the chain ID for the given chain. Returns an error if the chain ID is not supported.
    pub fn try_from_id(id: u64) -> eyre::Result<Self> {
        Self::from_id(id).ok_or_else(|| eyre::eyre!("chain id {} not supported", id))
    }

    /// Tries to get the chain ID from an online provider.
    pub async fn try_from_provider<T, P>(provider: &P) -> eyre::Result<Self>
    where
        T: Transport + Clone,
        P: Provider<T>,
    {
        let chain_id = provider.get_chain_id().await?;
        Self::try_from_id(chain_id)
    }
}

/// Styles for the CLI application.
const fn cli_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .usage(Style::new().bold().underline().fg_color(Some(Color::Ansi(AnsiColor::Yellow))))
        .header(Style::new().bold().underline().fg_color(Some(Color::Ansi(AnsiColor::Yellow))))
        .literal(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))))
        .invalid(Style::new().bold().fg_color(Some(Color::Ansi(AnsiColor::Red))))
        .error(Style::new().bold().fg_color(Some(Color::Ansi(AnsiColor::Red))))
        .valid(Style::new().bold().underline().fg_color(Some(Color::Ansi(AnsiColor::Green))))
        .placeholder(Style::new().fg_color(Some(Color::Ansi(AnsiColor::White))))
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
