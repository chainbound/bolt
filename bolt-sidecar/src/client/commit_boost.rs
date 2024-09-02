use std::sync::Arc;

use alloy::rpc::types::beacon::BlsSignature;
use cb_common::{
    commit::{client::SignerClient, request::SignConsensusRequest},
    signer::BlsPublicKey,
};
use eyre::ErrReport;
use parking_lot::RwLock;
use thiserror::Error;
use tracing::{debug, error, info};

use crate::crypto::bls::SignerBLSAsync;

/// A client for interacting with CommitBoost.
#[derive(Debug, Clone)]
pub struct CommitBoostClient {
    signer_client: SignerClient,
    pubkeys: Arc<RwLock<Vec<BlsPublicKey>>>,
}

#[derive(Debug, Error)]
pub enum CommitBoostError {
    #[error("failed to sign constraint: {0}")]
    NoSignature(String),
    #[error("failed to create signer client: {0}")]
    SignerClientError(#[from] ErrReport),
}

#[allow(unused)]
impl CommitBoostClient {
    /// Create a new [CommitBoostClient] instance
    pub async fn new(signer_server_address: String, jwt: &str) -> Result<Self, CommitBoostError> {
        let signer_client = SignerClient::new(signer_server_address, jwt)?;

        let client = Self { signer_client, pubkeys: Arc::new(RwLock::new(Vec::new())) };

        let mut this = client.clone();
        tokio::spawn(async move {
            match this.signer_client.get_pubkeys().await {
                Ok(pubkeys) => {
                    info!(consensus = pubkeys.consensus.len(), "Received pubkeys");
                    let mut pubkeys_lock = this.pubkeys.write();
                    *pubkeys_lock = pubkeys.consensus;
                }
                Err(e) => {
                    error!(?e, "Failed to fetch pubkeys");
                }
            }
        });

        Ok(client)
    }
}

#[async_trait::async_trait]
impl SignerBLSAsync for CommitBoostClient {
    async fn sign(&self, data: &[u8]) -> eyre::Result<BlsSignature> {
        let root = if data.len() == 32 {
            let mut root = [0u8; 32];
            root.copy_from_slice(data);
            Ok(root)
        } else {
            Err(CommitBoostError::NoSignature(format!(
                "invalid data length. Expected 32 bytes, found {} bytes",
                data.len()
            )))
        }?;

        let request =
            SignConsensusRequest::builder(*self.pubkeys.read().first().expect("pubkeys loaded"))
                .with_root(root);

        debug!(?request, "Requesting signature from commit_boost");

        Ok(self.signer_client.request_consensus_signature(request).await?)
    }
}
