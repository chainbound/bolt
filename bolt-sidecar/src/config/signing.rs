use clap::{ArgGroup, Args};

/// Command-line options for signing
#[derive(Debug, Clone, Args)]
#[clap(
    group = ArgGroup::new("signing-opts").required(true)
        .args(&["private_key", "commit_boost_url"])
)]
pub struct SigningOpts {
    /// Private key to use for signing preconfirmation requests
    #[clap(
        long,
        env = "BOLT_SIDECAR_PRIVATE_KEY",
        conflicts_with("commit_boost_url")
    )]
    pub(super) private_key: Option<String>,
    /// URL for the commit-boost sidecar
    #[clap(
        long,
        env = "BOLT_SIDECAR_COMMIT_BOOST_URL",
        conflicts_with("private_key")
    )]
    pub(super) commit_boost_url: Option<String>,
}
