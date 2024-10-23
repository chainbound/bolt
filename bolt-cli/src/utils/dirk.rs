use std::fs;

use eyre::{Context, Result};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::pb::ListerClient;

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
        let tls_config = credentials.compose()?;
        let conn = Channel::builder(addr).tls_config(tls_config)?.connect().await?;

        Ok(Self { conn })
    }

    pub fn list_accounts(&self) -> Result<()> {
        let lister = ListerClient::new(self.conn.clone());

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCredentials {
    client_cert_path: String,
    client_key_path: String,
    ca_cert_path: Option<String>,
}

impl TlsCredentials {
    pub fn new(
        client_cert_path: String,
        client_key_path: String,
        ca_cert_path: Option<String>,
    ) -> Self {
        Self { client_cert_path, client_key_path, ca_cert_path }
    }

    pub fn compose(self) -> Result<ClientTlsConfig> {
        let client_cert = fs::read(self.client_cert_path).wrap_err("Failed to read client cert")?;
        let client_key = fs::read(self.client_key_path).wrap_err("Failed to read client key")?;

        let ca_cert = if let Some(ca_path) = self.ca_cert_path {
            Some(fs::read(ca_path).wrap_err("Failed to read CA certificate")?)
        } else {
            None
        };

        create_tls_config(client_cert, client_key, ca_cert)
    }
}

// Helper function to create TLS config given the certificate, key, and CA certificate.
fn create_tls_config(
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
    ca_cert: Option<Vec<u8>>,
) -> Result<ClientTlsConfig> {
    // Create client identity (certificate + key)
    let identity = Identity::from_pem(&client_cert, &client_key);

    // Configure the TLS client
    let mut tls_config = ClientTlsConfig::new().identity(identity);

    // Optionally add CA certificate
    if let Some(ca_cert_data) = ca_cert {
        let ca_cert = Certificate::from_pem(&ca_cert_data);
        tls_config = tls_config.ca_certificate(ca_cert);
    }

    Ok(tls_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connect_to_dirk() -> eyre::Result<()> {
        let url = "http://localhost:9091".to_string();

        let test_data_dir = env!("CARGO_MANIFEST_DIR").to_string() + "/test_data/dirk";

        let cred = TlsCredentials {
            client_cert_path: test_data_dir.clone() + "/client1.crt",
            client_key_path: test_data_dir.clone() + "/client1.key",
            ca_cert_path: Some(test_data_dir.clone() + "/security/ca.crt"),
        };

        dbg!(&cred);

        let dirk = Dirk::connect(url, cred).await?;

        Ok(())
    }
}
