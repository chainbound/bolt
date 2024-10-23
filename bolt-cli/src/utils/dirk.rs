use std::fs;

use eyre::{Context, Result};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::{
    cli::TlsCredentials,
    pb::{Account, ListAccountsRequest, ListerClient},
};

/// A Dirk remote signer.
///
/// Reference: https://github.com/attestantio/dirk
#[derive(Clone)]
pub struct Dirk {
    conn: Channel,
}

impl Dirk {
    /// Connect to the DIRK server with the given address and TLS credentials.
    pub async fn connect(addr: String, credentials: TlsCredentials) -> Result<Self> {
        let addr = addr.parse()?;
        let tls_config = compose_credentials(credentials)?;
        let conn = Channel::builder(addr).tls_config(tls_config)?.connect().await?;

        Ok(Self { conn })
    }

    /// List all accounts in the keystore.
    pub async fn list_accounts(&self, paths: Vec<String>) -> Result<Vec<Account>> {
        let mut lister = ListerClient::new(self.conn.clone());
        let accs = lister.list_accounts(ListAccountsRequest { paths }).await?;

        Ok(accs.into_inner().accounts)
    }
}

/// Compose the TLS credentials from the given paths.
fn compose_credentials(creds: TlsCredentials) -> Result<ClientTlsConfig> {
    let client_cert = fs::read(creds.client_cert_path).wrap_err("Failed to read client cert")?;
    let client_key = fs::read(creds.client_key_path).wrap_err("Failed to read client key")?;

    // Create client identity (certificate + key)
    let identity = Identity::from_pem(&client_cert, &client_key);

    // Configure the TLS client
    let mut tls_config = ClientTlsConfig::new().identity(identity);

    // Add CA certificate if provided
    if let Some(ca_path) = creds.ca_cert_path {
        let ca_cert = fs::read(ca_path).wrap_err("Failed to read CA certificate")?;
        tls_config = tls_config.ca_certificate(Certificate::from_pem(&ca_cert));
    }

    Ok(tls_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test connecting to a DIRK server
    ///
    /// This test should be run manually against a running DIRK server.
    /// Eventually this could become part of the entire test setup but for now it's ignored.
    #[tokio::test]
    #[ignore]
    async fn test_connect_to_dirk() -> eyre::Result<()> {
        // Init the default rustls provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        let url = "https://localhost:9091".to_string();

        let test_data_dir = env!("CARGO_MANIFEST_DIR").to_string() + "/test_data/dirk";

        let cred = TlsCredentials {
            client_cert_path: test_data_dir.clone() + "/client1.crt",
            client_key_path: test_data_dir.clone() + "/client1.key",
            ca_cert_path: Some(test_data_dir.clone() + "/security/ca.crt"),
        };

        let dirk = Dirk::connect(url, cred).await?;

        let accounts = dirk.list_accounts(vec!["wallet1".to_string()]).await?;
        println!("Dirk Accounts: {:?}", accounts);

        Ok(())
    }
}
