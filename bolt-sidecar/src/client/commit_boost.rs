use std::sync::Arc;

use alloy::rpc::types::beacon::BlsSignature;
use cb_common::commit::{
    client::{GetPubkeysResponse, SignerClient},
    request::SignRequest,
};
use ethereum_consensus::ssz::prelude::ssz_rs;
use eyre::ErrReport;
use parking_lot::RwLock;
use thiserror::Error;
use tracing::{debug, error};

use crate::crypto::bls::SignerBLSAsync;

#[derive(Debug, Clone)]
pub struct CommitBoostClient {
    signer_client: SignerClient,
    pubkeys: Arc<RwLock<GetPubkeysResponse>>,
}

#[derive(Debug, Error)]
pub enum CommitBoostError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Deserialize(#[from] serde_json::Error),
    #[error("failed to compute hash tree root for constraint {0:?}")]
    HashTreeRoot(#[from] ssz_rs::MerkleizationError),
    #[error("failed to sign constraint: {0}")]
    NoSignature(String),
    #[error("failed to create signer client: {0}")]
    SignerClientError(#[from] ErrReport),
}

#[allow(unused)]
impl CommitBoostClient {
    /// Create a new [CommitBoostClient] instance
    pub async fn new(base_url: impl Into<String>) -> Result<Self, CommitBoostError> {
        let signer_client = SignerClient::new(base_url.into(), &"".to_string())?;

        let client = Self {
            signer_client,
            pubkeys: Arc::new(RwLock::new(GetPubkeysResponse { consensus: vec![], proxy: vec![] })),
        };

        let mut this = client.clone();
        tokio::spawn(async move {
            match this.signer_client.get_pubkeys().await {
                Ok(pubkeys) => {
                    let mut pubkeys_lock = this.pubkeys.write();
                    *pubkeys_lock = pubkeys;
                }
                Err(e) => {
                    eprintln!("Failed to load pubkeys: {}", e);
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
            SignRequest::builder(*self.pubkeys.read().consensus.first().expect("pubkeys loaded"))
                .with_root(root);

        debug!(?request, "Requesting signature from commit_boost");

        Ok(self.signer_client.request_signature(&request).await?)
    }
}
