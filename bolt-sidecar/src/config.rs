use std::str::FromStr;

use clap::Parser;

#[derive(Parser)]
pub(super) struct Opts {
    /// Port to listen on for incoming JSON-RPC requests.
    #[clap(short = 'p', long)]
    pub(super) port: Option<u16>,
    /// Private key to use for signing preconfirmation requests.
    #[clap(short = 'k', long)]
    pub(super) private_key: String,
    /// Max commitments to accept per block.
    #[clap(short = 'm', long)]
    pub(super) max_commitments: Option<usize>,
}

pub struct Config {
    pub rpc_port: u16,
    pub private_key: secp256k1::SecretKey,
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_port: 8000,
            private_key: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng()),
            limits: Limits::default(),
        }
    }
}

impl From<Opts> for Config {
    fn from(opts: Opts) -> Self {
        // Start with default config
        let mut config = Config::default();

        if let Some(port) = opts.port {
            config.rpc_port = port;
        }

        let private_key = secp256k1::SecretKey::from_str(&opts.private_key)
            .expect("Invalid secpk256k1 private key");

        config.private_key = private_key;

        if let Some(max_commitments) = opts.max_commitments {
            config.limits.max_commitments_per_block = max_commitments;
        }

        config
    }
}

pub struct Limits {
    pub max_commitments_per_block: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_commitments_per_block: 6,
        }
    }
}
