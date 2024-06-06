use blst::min_pk::SecretKey;
use clap::Parser;

use crate::crypto::bls::random_bls_secret;

/// Command-line options for the sidecar
#[derive(Parser, Debug)]
pub struct Opts {
    /// Port to listen on for incoming JSON-RPC requests
    #[clap(short = 'p', long)]
    pub(super) port: Option<u16>,
    /// Private key to use for signing preconfirmation requests
    #[clap(short = 'k', long)]
    pub(super) private_key: String,
    /// URL for the beacon client
    #[clap(short = 'c', long)]
    pub(super) beacon_client_url: String,
    /// URL for the MEV-Boost sidecar client to use
    #[clap(short = 'b', long)]
    pub(super) mevboost_url: String,
    /// URL for the beacon node API
    #[clap(short = 'c', long)]
    pub(super) beacon_url: String,
    /// Max commitments to accept per block
    #[clap(short = 'm', long)]
    pub(super) max_commitments: Option<usize>,
}

/// Configuration options for the sidecar
#[derive(Debug)]
pub struct Config {
    /// Port to listen on for incoming JSON-RPC requests
    pub rpc_port: u16,
    /// URL for the MEV-Boost sidecar client to use
    pub mevboost_url: String,
    /// URL for the beacon node API
    pub beacon_url: String,
    /// Private key to use for signing preconfirmation requests
    pub private_key: SecretKey,
    /// Limits for the sidecar
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_port: 8000,
            mevboost_url: "http://localhost:3030".to_string(),
            beacon_url: "http://localhost:5052".to_string(),
            private_key: random_bls_secret(),
            limits: Limits::default(),
        }
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

        config.beacon_url = opts.beacon_url.trim_end_matches('/').to_string();
        config.mevboost_url = opts.mevboost_url.trim_end_matches('/').to_string();
        config.private_key = SecretKey::from_bytes(&hex::decode(opts.private_key)?)
            .map_err(|e| eyre::eyre!("Failed decoding BLS secret key: {:?}", e))?;

        Ok(config)
    }
}

/// Limits for the sidecar.
#[derive(Debug)]
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
