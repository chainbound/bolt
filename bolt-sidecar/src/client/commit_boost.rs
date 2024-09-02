use std::sync::Arc;

use alloy::{rpc::types::beacon::BlsSignature, signers::Signature};
use cb_common::{
    commit::{
        client::SignerClient,
        request::{SignConsensusRequest, SignProxyRequest},
    },
    signer::{BlsPublicKey as CBBlsPublicKey, EcdsaPublicKey},
};
use eyre::ErrReport;
use parking_lot::RwLock;
use thiserror::Error;
use tracing::{debug, error, info};

use crate::crypto::{bls::SignerBLSAsync, ecdsa::SignerECDSAAsync};

/// A client for interacting with CommitBoost.
#[derive(Debug, Clone)]
pub struct CommitBoostSigner {
    /// A client for interacting with CommitBoost and handling signing operations.
    signer_client: SignerClient,
    pubkeys: Arc<RwLock<Vec<CBBlsPublicKey>>>,
    proxy_ecdsa: Arc<RwLock<Vec<EcdsaPublicKey>>>,
}

#[derive(Debug, Error)]
pub enum CommitBoostError {
    #[error("failed to sign constraint: {0}")]
    NoSignature(String),
    #[error("failed to create signer client: {0}")]
    SignerClientError(#[from] ErrReport),
}

#[allow(unused)]
impl CommitBoostSigner {
    /// Create a new [CommitBoostSigner] instance
    pub async fn new(signer_server_address: String, jwt: &str) -> Result<Self, CommitBoostError> {
        let signer_client = SignerClient::new(signer_server_address, jwt)?;

        let client = Self {
            signer_client,
            pubkeys: Arc::new(RwLock::new(Vec::new())),
            proxy_ecdsa: Arc::new(RwLock::new(Vec::new())),
        };

        let mut this = client.clone();
        tokio::spawn(async move {
            match this.signer_client.get_pubkeys().await {
                Ok(pubkeys) => {
                    info!(
                        consensus = pubkeys.consensus.len(),
                        bls_proxy = pubkeys.proxy_bls.len(),
                        ecdsa_proxy = pubkeys.proxy_ecdsa.len(),
                        "Received pubkeys"
                    );
                    let mut pubkeys_lock = this.pubkeys.write();
                    let mut proxy_ecdsa_lock = this.proxy_ecdsa.write();
                    *pubkeys_lock = pubkeys.consensus;
                    *proxy_ecdsa_lock = pubkeys.proxy_ecdsa;
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
impl SignerBLSAsync for CommitBoostSigner {
    async fn sign(&self, data: &[u8; 32]) -> eyre::Result<BlsSignature> {
        let request = SignConsensusRequest::builder(
            *self.pubkeys.read().first().expect("consensus pubkey loaded"),
        )
        .with_msg(data);

        debug!(?request, "Requesting signature from commit_boost");

        Ok(self.signer_client.request_consensus_signature(request).await?)
    }
}

#[async_trait::async_trait]
impl SignerECDSAAsync for CommitBoostSigner {
    async fn sign_hash(&self, hash: &[u8; 32]) -> eyre::Result<Signature> {
        let request = SignProxyRequest::builder(
            *self.proxy_ecdsa.read().first().expect("proxy ecdsa key loaded"),
        )
        .with_msg(hash);

        debug!(?request, "Requesting signature from commit_boost");

        let sig = self.signer_client.request_proxy_signature_ecdsa(request).await?;

        // Create an alloy signature from the raw bytes
        let alloy_sig = Signature::try_from(sig.as_ref())?;

        Ok(alloy_sig)
    }
}
