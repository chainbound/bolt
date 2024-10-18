use std::{fmt, net::SocketAddr, path::PathBuf};

use clap::{ArgGroup, Args};
use lighthouse_account_utils::ZeroizeString;
use serde::Deserialize;

use crate::common::{BlsSecretKeyWrapper, JwtSecretConfig};

/// Command-line options for signing
#[derive(Args, Deserialize, Debug)]
#[clap(
    group = ArgGroup::new("signing-opts").required(true)
        .args(&["private_key", "commit_boost_address", "keystore"])
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
    /// Options for the ERC-2335 keystore
    #[clap(flatten)]
    pub keystore: Option<KeystoreOpts>,
    /// Path to the delegations file. If not provided, the default path is used.
    #[clap(long, env = "BOLT_SIDECAR_DELEGATIONS_PATH")]
    pub delegations_path: Option<PathBuf>,
}

#[derive(Args, Deserialize)]
#[clap(
    group = ArgGroup::new("keystore-opts").required(true)
        .args(&["keystore_password", "keystore_secrets_path"])
)]
pub struct KeystoreOpts {
    /// The password for the ERC-2335 keystore.
    /// Reference: https://eips.ethereum.org/EIPS/eip-2335
    #[clap(long, env = "BOLT_SIDECAR_KEYSTORE_PASSWORD")]
    pub keystore_password: Option<ZeroizeString>,
    /// The path to the ERC-2335 keystore secret passwords
    /// Reference: https://eips.ethereum.org/EIPS/eip-2335
    #[clap(long, env = "BOLT_SIDECAR_KEYSTORE_SECRETS_PATH", conflicts_with("keystore_password"))]
    pub keystore_secrets_path: Option<PathBuf>,
    /// Path to the keystores folder. If not provided, the default path is used.
    #[clap(long, env = "BOLT_SIDECAR_KEYSTORE_PATH")]
    pub keystore_path: Option<PathBuf>,
}

// Implement Debug manually to hide the keystore_password field
impl fmt::Debug for KeystoreOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningOpts")
            .field("keystore_password", &"********") // Hides the actual password
            .field("keystore_path", &self.keystore_path)
            .field("keystore_secrets_path", &self.keystore_secrets_path)
            .finish()
    }
}
