use std::str::FromStr;

use clap::Parser;
use secp256k1::{rand, SecretKey};

/// Command-line options for the sidecar
#[derive(Parser, Debug)]
pub struct Opts {
    /// Port to listen on for incoming JSON-RPC requests
    #[clap(short = 'p', long)]
    pub(super) port: Option<u16>,
    /// Private key to use for signing preconfirmation requests
    #[clap(short = 'k', long)]
    pub(super) private_key: String,
    /// Max commitments to accept per block
    #[clap(short = 'm', long)]
    pub(super) max_commitments: Option<usize>,
}

/// Configuration options for the sidecar
#[derive(Debug)]
pub struct Config {
    /// Port to listen on for incoming JSON-RPC requests
    pub rpc_port: u16,
    /// Private key to use for signing preconfirmation requests
    pub private_key: SecretKey,
    /// Limits for the sidecar
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_port: 8000,
            private_key: SecretKey::new(&mut rand::thread_rng()),
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

        config.private_key = SecretKey::from_str(&opts.private_key)?;

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
