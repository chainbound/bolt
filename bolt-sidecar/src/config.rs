use blst::min_pk::SecretKey;
use clap::{ArgGroup, Args, Parser};

use crate::crypto::bls::random_bls_secret;

/// Command-line options for the sidecar
#[derive(Parser, Debug)]
pub struct Opts {
    /// Port to listen on for incoming JSON-RPC requests
    #[clap(short = 'p', long)]
    pub(super) port: Option<u16>,
    /// URL for the beacon client
    #[clap(short = 'c', long)]
    pub(super) beacon_api_url: String,
    /// URL for the MEV-Boost sidecar client to use
    #[clap(short = 'b', long)]
    pub(super) mevboost_url: String,
    /// Execution client API URL
    #[clap(short = 'x', long)]
    pub(super) execution_api_url: String,
    /// Execution client Engine API URL
    #[clap(short = 'e', long)]
    pub(super) engine_api_url: String,
    /// MEV-Boost proxy server port to use
    #[clap(short = 'y', long)]
    pub(super) mevboost_proxy_port: u16,
    /// Max commitments to accept per block
    #[clap(short = 'm', long)]
    pub(super) max_commitments: Option<usize>,
    /// Validator indexes
    #[clap(short = 'v', long, value_parser, num_args = 0.., value_delimiter = ',')]
    pub(super) validator_indexes: Vec<String>,
    /// Signing options
    #[clap(flatten)]
    pub(super) signing: SigningOpts,
}

/// Command-line options for signing
#[derive(Debug, Clone, Args)]
#[clap(
    group = ArgGroup::new("signing-opts").required(true)
        .args(&["private_key", "commit_boost_url"])
)]
pub struct SigningOpts {
    /// Private key to use for signing preconfirmation requests
    #[clap(short = 'k', long)]
    pub(super) private_key: Option<String>,
    /// URL for the commit-boost sidecar
    #[clap(short = 'C', long, conflicts_with("private_key"))]
    pub(super) commit_boost_url: Option<String>,
}

/// Configuration options for the sidecar
#[derive(Debug, Clone)]
pub struct Config {
    /// Port to listen on for incoming JSON-RPC requests
    pub rpc_port: u16,
    /// URL for the MEV-Boost sidecar client to use
    pub mevboost_url: String,
    /// URL for the commit-boost sidecar
    pub commit_boost_url: Option<String>,
    /// URL for the beacon client API URL
    pub beacon_api_url: String,
    /// Private key to use for signing preconfirmation requests
    pub private_key: Option<SecretKey>,
    /// The execution API url
    pub execution_api_url: String,
    /// The engine API url
    pub engine_api_url: String,
    /// The MEV-Boost proxy server port to use
    pub mevboost_proxy_port: u16,
    /// Limits for the sidecar
    pub limits: Limits,
    /// Validator indexes
    pub validator_indexes: Vec<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_port: 8000,
            mevboost_url: "http://localhost:3030".to_string(),
            commit_boost_url: None,
            beacon_api_url: "http://localhost:5052".to_string(),
            execution_api_url: "http://localhost:8545".to_string(),
            engine_api_url: "http://localhost:8551".to_string(),
            private_key: Some(random_bls_secret()),
            mevboost_proxy_port: 18551,
            limits: Limits::default(),
            validator_indexes: Vec::new(),
        }
    }
}

impl Config {
    /// Parse the command-line options and return a new `Config` instance
    pub fn parse_from_cli() -> eyre::Result<Self> {
        let opts = Opts::parse();
        Self::try_from(opts)
    }
}

impl TryFrom<Opts> for Config {
    type Error = eyre::Report;

    fn try_from(opts: Opts) -> eyre::Result<Self> {
        let mut config = Config::default();

        if let Some(port) = opts.port {
            config.rpc_port = port;
        }

        if let Some(max_commitments) = opts.max_commitments {
            config.limits.max_commitments_per_slot = max_commitments;
        }

        config.commit_boost_url = opts
            .signing
            .commit_boost_url
            .map(|url| url.trim_end_matches('/').to_string());

        config.private_key = if let Some(sk) = opts.signing.private_key {
            let sk = SecretKey::from_bytes(&hex::decode(sk)?)
                .map_err(|e| eyre::eyre!("Failed decoding BLS secret key: {:?}", e))?;
            Some(sk)
        } else {
            None
        };

        config.mevboost_proxy_port = opts.mevboost_proxy_port;
        config.engine_api_url = opts.engine_api_url.trim_end_matches('/').to_string();
        config.execution_api_url = opts.execution_api_url.trim_end_matches('/').to_string();
        config.beacon_api_url = opts.beacon_api_url.trim_end_matches('/').to_string();
        config.mevboost_url = opts.mevboost_url.trim_end_matches('/').to_string();

        if let Some(validator_indexes) = opts.validator_indexes {
            config.validator_indexes = parse_validator_indexes(&validator_indexes)?;
        }

        Ok(config)
    }
}

/// Parse the validator indexes input of the form - "1,2,3,4"
fn parse_validator_indexes(input: &str) -> eyre::Result<Vec<u64>> {
    input
        .trim_matches(|c| c == '"' || c == '"')
        .split(',')
        .map(|s| {
            s.trim()
                .parse()
                .map_err(|e| eyre::eyre!("Invalid index: {}: {:?}", s, e))
        })
        .collect()
}

/// Limits for the sidecar.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum number of commitments to accept per block
    pub max_commitments_per_slot: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_commitments_per_slot: 6,
        }
    }
}
