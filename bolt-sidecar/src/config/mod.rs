use std::{fs::File, io::Read};

use alloy::primitives::Address;
use clap::Parser;
use eyre::Context;
use reqwest::Url;
use serde::Deserialize;

pub mod validator_indexes;
pub use validator_indexes::ValidatorIndexes;

pub mod chain;
pub use chain::ChainConfig;

pub mod signing;
pub use signing::SigningOpts;

pub mod telemetry;
use telemetry::TelemetryOpts;

pub mod limits;
use limits::LimitsOpts;

use crate::common::{BlsSecretKeyWrapper, JwtSecretConfig};

/// Default port for the JSON-RPC server exposed by the sidecar.
pub const DEFAULT_RPC_PORT: u16 = 8000;

/// Default port for the Constraints proxy server.
pub const DEFAULT_CONSTRAINTS_PROXY_PORT: u16 = 18551;

/// Command-line options for the Bolt sidecar
#[derive(Debug, Parser, Deserialize)]
#[clap(trailing_var_arg = true)]
pub struct Opts {
    /// Port to listen on for incoming JSON-RPC requests
    #[clap(long, env = "BOLT_SIDECAR_PORT", default_value_t = DEFAULT_RPC_PORT)]
    pub port: u16,
    /// Execution client API URL
    #[clap(long, env = "BOLT_SIDECAR_EXECUTION_API_URL", default_value = "http://localhost:8545")]
    pub execution_api_url: Url,
    /// URL for the beacon client
    #[clap(long, env = "BOLT_SIDECAR_BEACON_API_URL", default_value = "http://localhost:5052")]
    pub beacon_api_url: Url,
    /// Execution client Engine API URL
    #[clap(long, env = "BOLT_SIDECAR_ENGINE_API_URL", default_value = "http://localhost:8551")]
    pub engine_api_url: Url,
    /// URL for the Constraint sidecar client to use
    #[clap(long, env = "BOLT_SIDECAR_CONSTRAINTS_URL", default_value = "http://localhost:3030")]
    pub constraints_url: Url,
    /// Constraint proxy server port to use
    #[clap(long, env = "BOLT_SIDECAR_CONSTRAINTS_PROXY_PORT", default_value_t = DEFAULT_CONSTRAINTS_PROXY_PORT)]
    pub constraints_proxy_port: u16,
    /// Validator indexes of connected validators that the sidecar
    /// should accept commitments on behalf of. Accepted values:
    /// - a comma-separated list of indexes (e.g. "1,2,3,4")
    /// - a contiguous range of indexes (e.g. "1..4")
    /// - a mix of the above (e.g. "1,2..4,6..8")
    #[clap(long, env = "BOLT_SIDECAR_VALIDATOR_INDEXES", default_value_t)]
    pub validator_indexes: ValidatorIndexes,
    /// The JWT secret token to authenticate calls to the engine API.
    ///
    /// It can either be a hex-encoded string or a file path to a file
    /// containing the hex-encoded secret.
    #[clap(long, env = "BOLT_SIDECAR_JWT_HEX")]
    pub jwt_hex: JwtSecretConfig,
    /// The fee recipient address for fallback blocks
    #[clap(long, env = "BOLT_SIDECAR_FEE_RECIPIENT")]
    pub fee_recipient: Address,
    /// Secret BLS key to sign fallback payloads with.
    #[clap(long, env = "BOLT_SIDECAR_BUILDER_PRIVATE_KEY")]
    pub builder_private_key: BlsSecretKeyWrapper,
    /// Operating limits for the sidecar
    #[clap(flatten)]
    pub limits: LimitsOpts,
    /// Chain config for the chain on which the sidecar is running
    #[clap(flatten)]
    pub chain: ChainConfig,
    /// Commitment signing options.
    #[clap(flatten)]
    pub signing: SigningOpts,
    /// Telemetry options
    #[clap(flatten)]
    pub telemetry: TelemetryOpts,
    /// Additional unrecognized arguments. Useful for CI and testing
    /// to avoid issues on potential extra flags provided (e.g. "--exact" from cargo nextest).
    #[cfg(test)]
    #[clap(allow_hyphen_values = true)]
    pub extra_args: Vec<String>,
}

impl Opts {
    /// Parse the configuration from a TOML file.
    pub fn parse_from_toml(file_path: &str) -> eyre::Result<Self> {
        let mut file = File::open(file_path).wrap_err("Unable to open file")?;

        let mut contents = String::new();
        file.read_to_string(&mut contents).wrap_err("Unable to read file")?;

        toml::from_str(&contents).wrap_err("Error parsing the TOML file")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let url = "http://0.0.0.0:3030";
        let parsed = url.parse::<Url>().unwrap();
        let socket_addr = parsed.socket_addrs(|| None).unwrap()[0];
        let localhost_socket = "0.0.0.0:3030".parse().unwrap();
        assert_eq!(socket_addr, localhost_socket);
    }

    #[test]
    fn test_parse_config_from_toml() {
        let path = env!("CARGO_MANIFEST_DIR").to_string() + "Config.toml";

        if let Ok(config_file) = std::fs::read_to_string(path) {
            let config = Opts::parse_from_toml(&config_file).expect("Failed to parse config");
            assert_eq!(config.execution_api_url, Url::parse("http://localhost:8545").unwrap());
            assert_eq!(config.beacon_api_url, Url::parse("http://localhost:5052").unwrap());
            assert_eq!(config.engine_api_url, Url::parse("http://localhost:8551").unwrap());
            assert_eq!(config.constraints_url, Url::parse("http://localhost:3030").unwrap());
            assert_eq!(config.constraints_proxy_port, 18551);
        }
    }
}
