use std::time::Duration;

use alloy_primitives::Address;
use blst::min_pk::SecretKey;
use clap::{ArgGroup, Args, Parser};

use crate::crypto::bls::random_bls_secret;

/// Default commitment deadline duration.
///
/// The sidecar will stop accepting new commitments for the next block
/// after this deadline has passed. This is to ensure that builders and
/// relays have enough time to build valid payloads.
pub const DEFAULT_COMMITMENT_DEADLINE: Duration = Duration::from_secs(8);

/// Default port for the JSON-RPC server exposed by the sidecar.
pub const DEFAULT_RPC_PORT: u16 = 8000;

/// Default port for the MEV-Boost proxy server.
pub const DEFAULT_MEV_BOOST_PROXY_PORT: u16 = 18551;

/// Command-line options for the Bolt sidecar
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
    /// Max number of commitments to accept per block
    #[clap(short = 'm', long)]
    pub(super) max_commitments: Option<usize>,
    /// The JWT secret token to authenticate calls to the engine API.
    ///
    /// It can either be a hex-encoded string or a file path to a file
    /// containing the hex-encoded secret.
    #[clap(short = 'j', long)]
    pub(super) jwt_hex: String,
    /// The fee recipient address for fallback blocks
    #[clap(short = 'f', long)]
    pub(super) fee_recipient: Address,
    /// Commitment signing options.
    #[clap(flatten)]
    pub(super) signing: SigningOpts,
    /// Secret BLS key to sign fallback payloads with
    /// (If not provided, a random key will be used)
    #[clap(short = 'k', long)]
    pub(super) builder_private_key: Option<String>,
    /// The deadline in the slot at which the sidecar will stop accepting
    /// new commitments for the next block (parsed as milliseconds)
    #[clap(short = 'd', long)]
    pub(super) commitment_deadline: Option<u64>,
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
    /// The jwt.hex secret to authenticate calls to the engine API
    pub jwt_hex: String,
    /// The fee recipient address for fallback blocks
    pub fee_recipient: Address,
    /// Limits for the sidecar
    pub limits: Limits,
    /// Local bulider private key
    pub builder_private_key: SecretKey,
    /// The deadline in the slot at which the sidecar will stop accepting
    /// new commitments for the next block
    pub commitment_deadline: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_port: DEFAULT_RPC_PORT,
            commit_boost_url: None,
            mevboost_url: "http://localhost:3030".to_string(),
            beacon_api_url: "http://localhost:5052".to_string(),
            execution_api_url: "http://localhost:8545".to_string(),
            engine_api_url: "http://localhost:8551".to_string(),
            private_key: Some(random_bls_secret()),
            mevboost_proxy_port: DEFAULT_MEV_BOOST_PROXY_PORT,
            jwt_hex: String::new(),
            fee_recipient: Address::ZERO,
            builder_private_key: random_bls_secret(),
            limits: Limits::default(),
            commitment_deadline: DEFAULT_COMMITMENT_DEADLINE,
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

        if let Some(builder_private_key) = opts.builder_private_key {
            let sk = SecretKey::from_bytes(&hex::decode(builder_private_key)?)
                .map_err(|e| eyre::eyre!("Failed decoding BLS secret key: {:?}", e))?;
            config.builder_private_key = sk;
        }

        config.jwt_hex = if opts.jwt_hex.starts_with("0x") {
            opts.jwt_hex.trim_start_matches("0x").to_string()
        } else if std::path::Path::new(&opts.jwt_hex).exists() {
            std::fs::read_to_string(opts.jwt_hex)?
                .trim_start_matches("0x")
                .to_string()
        } else {
            opts.jwt_hex
        };

        if let Some(deadline_ms) = opts.commitment_deadline {
            config.commitment_deadline = Duration::from_millis(deadline_ms);
        }

        // Validate the JWT secret
        if config.jwt_hex.len() != 64 {
            eyre::bail!("JWT secret must be a 32 byte hex string");
        } else {
            tracing::info!("JWT secret loaded successfully");
        }

        config.mevboost_proxy_port = opts.mevboost_proxy_port;
        config.engine_api_url = opts.engine_api_url.trim_end_matches('/').to_string();
        config.execution_api_url = opts.execution_api_url.trim_end_matches('/').to_string();
        config.beacon_api_url = opts.beacon_api_url.trim_end_matches('/').to_string();
        config.mevboost_url = opts.mevboost_url.trim_end_matches('/').to_string();

        Ok(config)
    }
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
