use std::fmt;

use clap::{ArgGroup, Args};
use lighthouse_account_utils::ZeroizeString;

/// Command-line options for signing
#[derive(Clone, Args)]
#[clap(
    group = ArgGroup::new("signing-opts").required(true)
        .args(&["private_key", "commit_boost_url", "commit_boost_jwt_hex"])
)]
pub struct SigningOpts {
    /// Private key to use for signing preconfirmation requests
    #[clap(long, env = "BOLT_SIDECAR_PRIVATE_KEY", group = "signing-opts")]
    pub(super) private_key: Option<String>,
    /// URL for the commit-boost sidecar
    #[clap(
        long,
        env = "BOLT_SIDECAR_CB_SIGNER_URL",
        group = "signing-opts",
        requires("commit_boost_jwt_hex")
    )]
    pub(super) commit_boost_url: Option<String>,
    /// JWT in hexadecimal format for authenticating with the commit-boost service
    #[clap(
        long,
        env = "BOLT_SIDECAR_CB_JWT_HEX",
        group = "signing-opts",
        requires("commit_boost_url")
    )]
    pub(super) commit_boost_jwt_hex: Option<String>,
    /// The password for the ERC-2335 keystore.
    /// Reference: https://eips.ethereum.org/EIPS/eip-2335
    #[clap(long, env = "BOLT_SIDECAR_KEYSTORE_PASSWORD", group = "signing-opts")]
    pub(super) keystore_password: Option<ZeroizeString>,
}

// Implement Debug manually to hide the keystore_password field
impl fmt::Debug for SigningOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningOpts")
            .field("private_key", &self.private_key)
            .field("commit_boost_url", &self.commit_boost_url)
            .field("commit_boost_jwt_hex", &self.commit_boost_jwt_hex)
            .field("keystore_password", &"********") // Hides the actual password
            .finish()
    }
}
