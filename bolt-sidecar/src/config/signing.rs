use std::{fmt, net::SocketAddr, ops::Deref};

use blst::min_pk::SecretKey;
use clap::{ArgGroup, Args};
use lighthouse_account_utils::ZeroizeString;
use rand::RngCore;

/// Command-line options for signing
#[derive(Args)]
#[clap(
    group = ArgGroup::new("signing-opts").required(true)
        .args(&["private_key", "commit_boost_url", "commit_boost_jwt_hex", "keystore_password"])
)]
pub struct SigningOpts {
    /// Private key to use for signing preconfirmation requests
    #[clap(long, env = "BOLT_SIDECAR_PRIVATE_KEY", group = "signing-opts")]
    pub private_key: Option<BlsSecretKey>,
    /// Socket address for the commit-boost sidecar
    #[clap(
        long,
        env = "BOLT_SIDECAR_CB_SIGNER_URL",
        group = "signing-opts",
        requires("commit_boost_jwt_hex")
    )]
    pub commit_boost_address: Option<SocketAddr>,
    /// JWT in hexadecimal format for authenticating with the commit-boost service
    #[clap(
        long,
        env = "BOLT_SIDECAR_CB_JWT_HEX",
        group = "signing-opts",
        requires("commit_boost_url")
    )]
    pub commit_boost_jwt_hex: Option<String>,
    /// The password for the ERC-2335 keystore.
    /// Reference: https://eips.ethereum.org/EIPS/eip-2335
    #[clap(long, env = "BOLT_SIDECAR_KEYSTORE_PASSWORD", group = "signing-opts")]
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
            private_key: Some(BlsSecretKey::random_bls_secret()),
            commit_boost_address: None,
            commit_boost_jwt_hex: None,
            keystore_password: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlsSecretKey(pub SecretKey);

impl BlsSecretKey {
    pub fn random_bls_secret() -> Self {
        let mut rng = rand::thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        Self(SecretKey::key_gen(&ikm, &[]).unwrap())
    }
}

impl From<&str> for BlsSecretKey {
    fn from(sk: &str) -> Self {
        let hex_sk = sk.strip_prefix("0x").unwrap_or(sk);
        let sk = SecretKey::from_bytes(&hex::decode(hex_sk).expect("valid hex")).expect("valid sk");
        BlsSecretKey(sk)
    }
}

impl Deref for BlsSecretKey {
    type Target = SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for BlsSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.to_bytes()))
    }
}
