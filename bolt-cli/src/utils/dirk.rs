use std::fs;

use alloy_primitives::B256;
use ethereum_consensus::crypto::bls::{PublicKey as BlsPublicKey, Signature as BlsSignature};
use eyre::{Context, Result};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::{
    cli::TlsCredentials,
    pb::eth2_signer_api::{
        Account, ListAccountsRequest, ListerClient, SignRequest, SignRequestId, SignerClient,
    },
};

/// A Dirk remote signer.
///
/// Reference: https://github.com/attestantio/dirk
#[derive(Clone)]
pub struct Dirk {
    lister: ListerClient<Channel>,
    signer: SignerClient<Channel>,
}

impl Dirk {
    /// Connect to the DIRK server with the given address and TLS credentials.
    pub async fn connect(addr: String, credentials: TlsCredentials) -> Result<Self> {
        let addr = addr.parse()?;
        let tls_config = compose_credentials(credentials)?;
        let conn = Channel::builder(addr).tls_config(tls_config)?.connect().await?;

        let lister = ListerClient::new(conn.clone());
        let signer = SignerClient::new(conn.clone());

        Ok(Self { lister, signer })
    }

    /// List all accounts in the keystore.
    pub async fn list_accounts(&mut self, paths: Vec<String>) -> Result<Vec<Account>> {
        let accs = self.lister.list_accounts(ListAccountsRequest { paths }).await?;

        Ok(accs.into_inner().accounts)
    }

    /// Request a signature from the remote signer.
    pub async fn request_signature(
        &mut self,
        pubkey: BlsPublicKey,
        hash: B256,
        domain: B256,
    ) -> Result<BlsSignature> {
        let req = SignRequest {
            data: hash.to_vec(),
            domain: domain.to_vec(),
            id: Some(SignRequestId::PublicKey(pubkey.to_vec())),
        };

        let res = self.signer.sign(req).await?;
        let sig = res.into_inner().signature;
        let sig = BlsSignature::try_from(sig.as_slice()).wrap_err("Failed to parse signature")?;

        Ok(sig)
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
    use std::{process::Command, time::Duration};

    use super::*;

    /// Test connecting to a DIRK server and listing available accounts.
    ///
    /// ```shell
    /// cargo test --package bolt-cli --bin bolt-cli -- utils::dirk::tests::test_dirk_connection_e2e
    /// --exact --show-output --ignored
    /// ```
    #[tokio::test]
    #[ignore]
    async fn test_dirk_connection_e2e() -> eyre::Result<()> {
        // Init the default rustls provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        let test_data_dir = env!("CARGO_MANIFEST_DIR").to_string() + "/test_data/dirk";

        // Init the DIRK config file
        init_dirk_config(test_data_dir.clone())?;

        // Check if dirk is installed (in $PATH)
        if Command::new("dirk")
            .arg("--base-dir")
            .arg(&test_data_dir)
            .arg("--help")
            .status()
            .is_err()
        {
            eprintln!("DIRK is not installed in $PATH");
            return Ok(());
        }

        // Start the DIRK server in the background
        let mut dirk_proc = Command::new("dirk").arg("--base-dir").arg(&test_data_dir).spawn()?;

        // Wait for some time for the server to start up
        tokio::time::sleep(Duration::from_secs(3)).await;

        let url = "https://localhost:9091".to_string();

        let cred = TlsCredentials {
            client_cert_path: test_data_dir.clone() + "/client1.crt",
            client_key_path: test_data_dir.clone() + "/client1.key",
            ca_cert_path: Some(test_data_dir.clone() + "/security/ca.crt"),
        };

        let mut dirk = Dirk::connect(url, cred).await?;

        let accounts = dirk.list_accounts(vec!["wallet1".to_string()]).await?;
        println!("Dirk Accounts: {:?}", accounts);

        // make sure to stop the dirk server
        dirk_proc.kill()?;

        Ok(())
    }

    fn init_dirk_config(test_data_dir: String) -> eyre::Result<()> {
        // read the template json file from test_data
        let template_path = test_data_dir.clone() + "/dirk.template.json";
        let template = fs::read_to_string(template_path).wrap_err("Failed to read template")?;

        // change the occurrence of $PWD to the current working directory in the template
        let new_file = test_data_dir.clone() + "/dirk.json";
        let new_content = template.replace("$PWD", &test_data_dir);
        fs::write(new_file, new_content).wrap_err("Failed to write dirk config file")?;

        Ok(())
    }
}
