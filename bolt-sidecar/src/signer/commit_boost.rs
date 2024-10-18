use std::{str::FromStr, sync::Arc};

use alloy::{rpc::types::beacon::BlsSignature, signers::Signature};
use cb_common::{
    commit::{client::SignerClient, error::SignerClientError, request::SignConsensusRequest},
    signer::EcdsaPublicKey,
};
use commit_boost::prelude::SignProxyRequest;
use ethereum_consensus::crypto::bls::PublicKey as BlsPublicKey;
use parking_lot::RwLock;
use reqwest::Url;
use thiserror::Error;
use tracing::{debug, error, info};

use crate::{
    crypto::{bls::BLS_DST_PREFIX, ecdsa::SignerECDSA},
    primitives::commitment::ECDSASignatureExt,
};

use super::SignerResult;

/// A client for interacting with CommitBoost.
#[derive(Debug, Clone)]
pub struct CommitBoostSigner {
    /// A client for interacting with CommitBoost and handling signing operations.
    signer_client: SignerClient,
    pubkeys: Arc<RwLock<Vec<BlsPublicKey>>>,
    proxy_ecdsa: Arc<RwLock<Vec<EcdsaPublicKey>>>,
}

#[derive(Debug, Error)]
pub enum CommitBoostError {
    #[error("failed to sign constraint: {0}")]
    NoSignature(String),
    #[error("failed to create signer client: {0}")]
    SignerClientError(#[from] SignerClientError),
    #[error("error in commit boost signer: {0}")]
    Other(String),
}

#[allow(unused)]
impl CommitBoostSigner {
    /// Create a new [CommitBoostSigner] instance
    pub fn new(signer_url: Url, jwt: &str) -> SignerResult<Self> {
        let Some(hostname) = signer_url.host_str() else {
            return Err(CommitBoostError::Other("Invalid signer host".to_string()).into());
        };

        let signer_server_address = format!("{}:{}", hostname, signer_url.port().unwrap_or(80));

        let signer_client = match SignerClient::new(signer_server_address, jwt) {
            Ok(client) => client,
            Err(e) => return Err(CommitBoostError::Other(e.to_string()).into()),
        };

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
                    *pubkeys_lock = pubkeys
                        .consensus
                        .into_iter()
                        .map(|k| BlsPublicKey::try_from(k.as_ref()).unwrap())
                        .collect();
                    *proxy_ecdsa_lock = pubkeys.proxy_ecdsa;
                }
                Err(e) => {
                    error!(?e, "Failed to fetch pubkeys");
                }
            }
        });

        Ok(client)
    }

    /// Get the consensus public key from the Commit-Boost signer.
    pub fn get_consensus_pubkey(&self) -> BlsPublicKey {
        let pk = self.pubkeys.read().first().expect("consensus pubkey loaded").clone();
        BlsPublicKey::try_from(pk.as_ref()).expect("consensus pubkey is valid")
    }

    /// Get the proxy ECDSA public key from the Commit-Boost signer.
    pub fn get_proxy_ecdsa_pubkey(&self) -> EcdsaPublicKey {
        *self.proxy_ecdsa.read().first().expect("proxy ecdsa key loaded")
    }

    /// Verify the BLS signature of the object with the given public key.
    ///
    /// Note: The default implementation should be used where possible.
    pub fn verify_bls(
        &self,
        data: &[u8; 32],
        sig: &blst::min_pk::Signature,
        pubkey: &blst::min_pk::PublicKey,
    ) -> bool {
        sig.verify(false, data, BLS_DST_PREFIX, &[], pubkey, true) == blst::BLST_ERROR::BLST_SUCCESS
    }

    /// Verify the ECDSA signature of the object with the given public key.
    ///
    /// Note: The default implementation should be used where possible.
    pub fn verify_ecdsa(&self, data: &[u8; 32], sig: &Signature, pubkey: &EcdsaPublicKey) -> bool {
        let sig = secp256k1::ecdsa::Signature::from_str(&sig.to_hex()).expect("signature is valid");
        let pubkey =
            secp256k1::PublicKey::from_slice(pubkey.as_ref()).expect("public key is valid");
        secp256k1::Secp256k1::new()
            .verify_ecdsa(&secp256k1::Message::from_digest(*data), &sig, &pubkey)
            .is_ok()
    }
}

impl CommitBoostSigner {
    /// Get the public key of the signer.
    pub fn pubkey(&self) -> BlsPublicKey {
        self.get_consensus_pubkey()
    }

    /// Sign an object root with the Commit Boost domain.
    pub async fn sign_commit_boost_root(&self, data: [u8; 32]) -> SignerResult<BlsSignature> {
        // convert the pubkey from ethereum_consensus to commit-boost format
        let pubkey = cb_common::signer::BlsPublicKey::from(
            alloy::rpc::types::beacon::BlsPublicKey::from_slice(self.pubkey().as_ref()),
        );

        let request = SignConsensusRequest { pubkey, object_root: data };

        debug!(?request, "Requesting signature from commit_boost");

        Ok(self
            .signer_client
            .request_consensus_signature(request)
            .await
            .map_err(CommitBoostError::SignerClientError)?)
    }
}

#[async_trait::async_trait]
impl SignerECDSA for CommitBoostSigner {
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

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;
    use tracing::warn;

    #[tokio::test]
    async fn test_bls_commit_boost_signer() -> eyre::Result<()> {
        let _ = dotenvy::dotenv();

        let (signer_server_address, jwt_hex) = match (
            std::env::var("BOLT_SIDECAR_CB_SIGNER_URL").ok(),
            std::env::var("BOLT_SIDECAR_CB_JWT_HEX"),
        ) {
            (Some(address), Ok(hex)) => (address, hex),
            _ => {
                warn!("skipping test: commit-boost inputs are not set");
                return Ok(());
            }
        };
        let signer = CommitBoostSigner::new(signer_server_address.parse()?, &jwt_hex).unwrap();

        // Generate random data for the test
        let mut rng = rand::thread_rng();
        let mut data = [0u8; 32];
        rng.fill(&mut data);

        let signature = signer.sign_commit_boost_root(data).await.unwrap();
        let sig = blst::min_pk::Signature::from_bytes(signature.as_ref()).unwrap();
        let pubkey = signer.get_consensus_pubkey();
        let bls_pubkey = blst::min_pk::PublicKey::from_bytes(pubkey.as_ref()).unwrap();
        assert!(signer.verify_bls(&data, &sig, &bls_pubkey));

        Ok(())
    }

    #[tokio::test]
    async fn test_ecdsa_commit_boost_signer() -> eyre::Result<()> {
        let _ = dotenvy::dotenv();

        let (signer_server_address, jwt_hex) = match (
            std::env::var("BOLT_SIDECAR_CB_SIGNER_URL").ok(),
            std::env::var("BOLT_SIDECAR_CB_JWT_HEX"),
        ) {
            (Some(address), Ok(hex)) => (address, hex),
            _ => {
                warn!("skipping test: commit-boost inputs are not set");
                return Ok(());
            }
        };
        let signer = CommitBoostSigner::new(signer_server_address.parse()?, &jwt_hex).unwrap();
        let pubkey = signer.get_proxy_ecdsa_pubkey();

        // Generate random data for the test
        let mut rng = rand::thread_rng();
        let mut data = [0u8; 32];
        rng.fill(&mut data);

        let signature = signer.sign_hash(&data).await.unwrap();
        assert!(signer.verify_ecdsa(&data, &signature, &pubkey));

        Ok(())
    }
}
