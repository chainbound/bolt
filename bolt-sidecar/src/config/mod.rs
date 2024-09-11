use std::{fs::read_to_string, path::Path, str::FromStr};

use alloy::primitives::Address;
use blst::min_pk::SecretKey;
use clap::Parser;
use eyre::{bail, eyre, Report, Result};
use reqwest::Url;
use std::num::NonZero;
use tracing::info;

use crate::crypto::bls::random_bls_secret;

pub mod validator_indexes;
pub use validator_indexes::ValidatorIndexes;

pub mod chain;
pub use chain::ChainConfig;

pub mod signing;
pub use signing::SigningOpts;

pub mod telemetry;
use telemetry::TelemetryOpts;

/// Default port for the JSON-RPC server exposed by the sidecar.
pub const DEFAULT_RPC_PORT: u16 = 8000;

/// Default port for the Constraints proxy server.
pub const DEFAULT_CONSTRAINTS_PROXY_PORT: u16 = 18551;

/// Command-line options for the Bolt sidecar
#[derive(Parser, Debug)]
pub struct Opts {
    /// Port to listen on for incoming JSON-RPC requests
    #[clap(long, env = "BOLT_SIDECAR_PORT")]
    pub(super) port: Option<u16>,
    /// URL for the beacon client
    #[clap(long, env = "BOLT_SIDECAR_BEACON_API")]
    pub(super) beacon_api_url: String,
    /// URL for the Constraint sidecar client to use
    #[clap(long, env = "BOLT_SIDECAR_CONSTRAINTS_URL")]
    pub(super) constraints_url: String,
    /// Execution client API URL
    #[clap(long, env = "BOLT_SIDECAR_EXECUTION_API")]
    pub(super) execution_api_url: String,
    /// Execution client Engine API URL
    #[clap(long, env = "BOLT_SIDECAR_ENGINE_API")]
    pub(super) engine_api_url: String,
    /// Constraint proxy server port to use
    #[clap(long, env = "BOLT_SIDECAR_CONSTRAINTS_PROXY_PORT")]
    pub(super) constraints_proxy_port: u16,
    /// Max number of commitments to accept per block
    #[clap(long, env = "BOLT_SIDECAR_MAX_COMMITMENTS")]
    pub(super) max_commitments: Option<NonZero<usize>>,
    /// Max committed gas per slot
    #[clap(long, env = "BOLT_SIDECAR_MAX_COMMITTED_GAS")]
    pub(super) max_committed_gas: Option<NonZero<u64>>,
    /// Validator indexes of connected validators that the sidecar
    /// should accept commitments on behalf of. Accepted values:
    /// - a comma-separated list of indexes (e.g. "1,2,3,4")
    /// - a contiguous range of indexes (e.g. "1..4")
    /// - a mix of the above (e.g. "1,2..4,6..8")
    #[clap(long, value_parser = ValidatorIndexes::from_str, env = "BOLT_SIDECAR_VALIDATOR_INDEXES")]
    pub(super) validator_indexes: ValidatorIndexes,
    /// The JWT secret token to authenticate calls to the engine API.
    ///
    /// It can either be a hex-encoded string or a file path to a file
    /// containing the hex-encoded secret.
    #[clap(long, env = "BOLT_SIDECAR_JWT_HEX")]
    pub(super) jwt_hex: String,
    /// The fee recipient address for fallback blocks
    #[clap(long, env = "BOLT_SIDECAR_FEE_RECIPIENT")]
    pub(super) fee_recipient: Address,
    /// Secret BLS key to sign fallback payloads with
    /// (If not provided, a random key will be used)
    #[clap(long, env = "BOLT_SIDECAR_BUILDER_PRIVATE_KEY")]
    pub(super) builder_private_key: Option<String>,
    /// Chain config for the chain on which the sidecar is running
    #[clap(flatten)]
    pub(super) chain: ChainConfig,
    /// Commitment signing options.
    #[clap(flatten)]
    pub(super) signing: SigningOpts,
    /// Telemetry options
    #[clap(flatten)]
    pub(super) telemetry: TelemetryOpts,
}

/// Configuration options for the sidecar. These are parsed from
/// command-line options in the form of [`Opts`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Port to listen on for incoming JSON-RPC requests
    pub rpc_port: u16,
    /// The Constraints client proxy server port to listen on
    pub constraints_proxy_port: u16,
    /// URL for the Constraints sidecar client to use
    pub constraints_url: Url,
    /// URL for the beacon client API URL
    pub beacon_api_url: Url,
    /// The execution API url
    pub execution_api_url: Url,
    /// The engine API url
    pub engine_api_url: Url,
    /// URL for the commit-boost sidecar
    pub commit_boost_address: Option<String>,
    /// The JWT secret token to authenticate calls to the commit-boost
    pub commit_boost_jwt_hex: Option<String>,
    /// Private key to use for signing preconfirmation requests
    pub private_key: Option<SecretKey>,
    /// The jwt.hex secret to authenticate calls to the engine API
    pub jwt_hex: String,
    /// The fee recipient address for fallback blocks
    pub fee_recipient: Address,
    /// Operating limits for the sidecar
    pub limits: Limits,
    /// Validator indexes of connected validators that the
    /// sidecar should accept commitments on behalf of
    pub validator_indexes: ValidatorIndexes,
    /// Local bulider private key for signing fallback payloads.
    /// If not provided, a random key will be used.
    pub builder_private_key: SecretKey,
    /// The chain on which the sidecar is running
    pub chain: ChainConfig,
    /// Metrics port
    pub metrics_port: u16,
    /// Toggle for metrics
    pub disable_metrics: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_port: DEFAULT_RPC_PORT,
            constraints_proxy_port: DEFAULT_CONSTRAINTS_PROXY_PORT,
            commit_boost_address: None,
            commit_boost_jwt_hex: None,
            constraints_url: "http://localhost:3030".parse().expect("Valid URL"),
            beacon_api_url: "http://localhost:5052".parse().expect("Valid URL"),
            execution_api_url: "http://localhost:8545".parse().expect("Valid URL"),
            engine_api_url: "http://localhost:8551".parse().expect("Valid URL"),
            private_key: Some(random_bls_secret()),
            jwt_hex: String::new(),
            fee_recipient: Address::ZERO,
            builder_private_key: random_bls_secret(),
            limits: Limits::default(),
            validator_indexes: ValidatorIndexes::default(),
            chain: ChainConfig::default(),
            metrics_port: 0,
            disable_metrics: false,
        }
    }
}

/// Limits for the sidecar.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum number of commitments to accept per block
    pub max_commitments_per_slot: NonZero<usize>,
    pub max_committed_gas_per_slot: NonZero<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_commitments_per_slot: NonZero::new(128).expect("Valid non-zero"),
            max_committed_gas_per_slot: NonZero::new(10_000_000).expect("Valid non-zero"),
        }
    }
}

impl Config {
    /// Parse the command-line options and return a new [`Config`] instance
    pub fn parse_from_cli() -> Result<Self> {
        let opts = Opts::parse();
        Self::try_from(opts)
    }
}

impl TryFrom<Opts> for Config {
    type Error = Report;

    fn try_from(opts: Opts) -> Result<Self, Self::Error> {
        let mut config = Config::default();

        if let Some(port) = opts.port {
            config.rpc_port = port;
        }

        if let Some(max_commitments) = opts.max_commitments {
            config.limits.max_commitments_per_slot = max_commitments;
        }

        if let Some(max_committed_gas) = opts.max_committed_gas {
            config.limits.max_committed_gas_per_slot = max_committed_gas;
        }

        if let Some(commit_boost_url) = &opts.signing.commit_boost_url {
            config.commit_boost_address = Some(commit_boost_url.clone());
        }

        if let Some(cb_jwt) = &opts.signing.commit_boost_jwt_hex {
            config.commit_boost_jwt_hex = Some(cb_jwt.clone());
        }

        config.private_key = if let Some(sk) = opts.signing.private_key {
            let hex_sk = sk.strip_prefix("0x").unwrap_or(&sk);
            let sk = SecretKey::from_bytes(&hex::decode(hex_sk)?)
                .map_err(|e| eyre!("Failed decoding BLS signer secret key: {:?}", e))?;
            Some(sk)
        } else {
            None
        };

        if let Some(builder_sk) = opts.builder_private_key {
            let hex_sk = builder_sk.strip_prefix("0x").unwrap_or(&builder_sk);
            let sk = SecretKey::from_bytes(&hex::decode(hex_sk)?)
                .map_err(|e| eyre!("Failed decoding BLS builder secret key: {:?}", e))?;
            config.builder_private_key = sk;
        }

        config.jwt_hex = if opts.jwt_hex.starts_with("0x") {
            opts.jwt_hex.trim_start_matches("0x").to_string()
        } else if Path::new(&opts.jwt_hex).exists() {
            read_to_string(opts.jwt_hex)
                .map_err(|e| eyre!("Failed reading JWT secret file: {:?}", e))?
                .trim_start_matches("0x")
                .to_string()
        } else {
            opts.jwt_hex
        };

        // Validate the JWT secret
        if config.jwt_hex.len() != 64 {
            bail!("Engine JWT secret must be a 32 byte hex string");
        } else {
            info!("Engine JWT secret loaded successfully");
        }

        config.constraints_proxy_port = opts.constraints_proxy_port;
        config.engine_api_url = opts.engine_api_url.parse()?;
        config.execution_api_url = opts.execution_api_url.parse()?;
        config.beacon_api_url = opts.beacon_api_url.parse()?;
        config.constraints_url = opts.constraints_url.parse()?;

        config.fee_recipient = opts.fee_recipient;

        config.validator_indexes = opts.validator_indexes;

        config.chain = opts.chain;
        config.metrics_port = opts.telemetry.metrics_port;
        config.disable_metrics = opts.telemetry.disable_metrics;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url() {
        let url = "http://0.0.0.0:3030";
        let parsed = url.parse::<Url>().unwrap();
        let socket_addr = parsed.socket_addrs(|| None).unwrap()[0];
        let localhost_socket = "0.0.0.0:3030".parse().unwrap();
        assert_eq!(socket_addr, localhost_socket);
    }
}
