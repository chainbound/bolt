use clap::{ArgGroup, Args};

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
