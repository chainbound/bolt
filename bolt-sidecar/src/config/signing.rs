use clap::Args;

/// Command-line options for signing
#[derive(Debug, Clone, Args)]
#[group(required = true, multiple = true)]
pub struct SigningOpts {
    /// Private key to use for signing preconfirmation requests
    #[clap(long, env = "BOLT_SIDECAR_PRIVATE_KEY", conflicts_with("commit_boost_url"))]
    pub(super) private_key: Option<String>,
    /// URL for the commit-boost sidecar
    #[clap(
        long,
        env = "SIGNER_SERVER",
        conflicts_with("private_key"),
        requires("commit_boost_jwt_hex")
    )]
    pub(super) commit_boost_url: Option<String>,
    /// JWT in hexadecimal format for authenticating with the commit-boost service
    #[clap(
        long,
        env = "CB_SIGNER_JWT",
        conflicts_with("private_key"),
        requires("commit_boost_url")
    )]
    pub(super) commit_boost_jwt_hex: Option<String>,
}
