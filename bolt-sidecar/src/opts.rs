use clap::Parser;

#[derive(Parser)]
pub(super) struct Opts {
    /// Port to listen on for incoming JSON-RPC requests.
    #[clap(short = 'p', long, default_value = "8000")]
    pub(super) port: u16,
    /// Private key to use for signing preconfirmation requests.
    #[clap(short = 'k', long)]
    pub(super) private_key: Option<String>,
}
