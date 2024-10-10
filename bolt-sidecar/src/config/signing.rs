use crate::common::{BlsSecretKeyWrapper, JwtSecretConfig};
use std::{
    fmt::{self},
    net::SocketAddr,
};

use clap::{ArgGroup, Args};
use lighthouse_account_utils::ZeroizeString;

/// Command-line options for signing
#[derive(Args)]
#[clap(
    group = ArgGroup::new("signing-opts").required(true)
        .args(&["private_key", "commit_boost_address", "commit_boost_jwt_hex", "keystore_password"])
)]
pub struct SigningOpts {
    /// Private key to use for signing preconfirmation requests
    #[clap(long, env = "BOLT_SIDECAR_PRIVATE_KEY")]
    pub private_key: Option<BlsSecretKeyWrapper>,
    /// Socket address for the commit-boost sidecar
    #[clap(long, env = "BOLT_SIDECAR_CB_SIGNER_URL", requires("commit_boost_jwt_hex"))]
    pub commit_boost_address: Option<SocketAddr>,
    /// JWT in hexadecimal format for authenticating with the commit-boost service
    #[clap(long, env = "BOLT_SIDECAR_CB_JWT_HEX", requires("commit_boost_address"))]
    pub commit_boost_jwt_hex: Option<JwtSecretConfig>,
    /// The password for the ERC-2335 keystore.
    /// Reference: https://eips.ethereum.org/EIPS/eip-2335
    #[clap(long, env = "BOLT_SIDECAR_KEYSTORE_PASSWORD")]
    pub keystore_password: Option<ZeroizeString>,
}

// Implement Debug manually to hide the keystore_password field
impl fmt::Debug for SigningOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningOpts")
            .field("private_key", &self.private_key)
            .field("commit_boost_url", &self.commit_boost_address)
            .field("commit_boost_jwt_hex", &self.commit_boost_jwt_hex)
            .field("keystore_password", &"********") // Hides the actual password
            .finish()
    }
}

impl Default for SigningOpts {
    fn default() -> Self {
        Self {
            private_key: Some(BlsSecretKeyWrapper::random()),
            commit_boost_address: None,
            commit_boost_jwt_hex: None,
            keystore_password: None,
        }
    }
}
