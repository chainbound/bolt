use clap::Parser;

#[derive(Parser)]
pub(super) struct Opts {
    /// Port to listen on for incoming JSON-RPC requests.
    #[clap(short = 'p', long)]
    pub(super) port: Option<u16>,
    /// BLS private key to use for signing commitment requests.
    #[clap(short = 'k', long)]
    pub(super) private_key: String,
    /// Max commitments to accept per block.
    #[clap(short = 'm', long)]
    pub(super) max_commitments: Option<usize>,
}

pub struct Config {
    pub rpc_port: u16,
    pub private_key: blst::min_pk::SecretKey,
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_port: 8000,
            private_key: blst::min_pk::SecretKey::default(),
            limits: Limits::default(),
        }
    }
}

impl TryFrom<Opts> for Config {
    type Error = eyre::Report;

    fn try_from(opts: Opts) -> eyre::Result<Self> {
        // Start with default config
        let mut config = Config::default();

        if let Some(port) = opts.port {
            config.rpc_port = port;
        }

        let private_key = blst::min_pk::SecretKey::from_bytes(&hex::decode(opts.private_key)?)
            .map_err(|e| eyre::eyre!("failed to parse private key: {:?}", e))?;

        config.private_key = private_key;

        if let Some(max_commitments) = opts.max_commitments {
            config.limits.max_commitments_per_block = max_commitments;
        }

        Ok(config)
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
