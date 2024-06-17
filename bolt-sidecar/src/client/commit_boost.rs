use std::sync::Arc;

use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use cb_common::pbs::{COMMIT_BOOST_API, PUBKEYS_PATH, SIGN_REQUEST_PATH};
use cb_crypto::types::SignRequest;
use ethereum_consensus::ssz::prelude::ssz_rs;
use parking_lot::RwLock;
use thiserror::Error;

use crate::crypto::bls::SignerBLSAsync;

const SIGN_REQUEST_ID: &str = "bolt";

#[derive(Debug, Clone)]
pub struct CommitBoostClient {
    base_url: String,
    client: reqwest::Client,
    pubkeys: Arc<RwLock<Vec<BlsPublicKey>>>,
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
}

impl CommitBoostClient {
    pub async fn new(base_url: impl Into<String>) -> Result<Self, CommitBoostError> {
        let client = Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
            pubkeys: Arc::new(RwLock::new(Vec::new())),
        };

        let mut this = client.clone();
        tokio::spawn(async move {
            this.load_pubkeys().await.expect("failed to load pubkeys");
        });

        Ok(client)
    }

    async fn load_pubkeys(&mut self) -> Result<(), CommitBoostError> {
        loop {
            let url = self.url_from_path(PUBKEYS_PATH);

            tracing::info!(url, "Loading public keys from commit-boost");

            let response = match self.client.get(url).send().await {
                Ok(res) => res,
                Err(e) => {
                    tracing::error!(err = ?e, "failed to get public keys from commit-boost, retrying...");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let status = response.status();
            let response_bytes = response.bytes().await?;

            if !status.is_success() {
                let err = String::from_utf8_lossy(&response_bytes).into_owned();
                tracing::error!(err, ?status, "failed to get public keys, retrying...");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            let pubkeys: Vec<BlsPublicKey> = serde_json::from_slice(&response_bytes)?;

            {
                let mut pk = self.pubkeys.write();
                *pk = pubkeys;
                return Ok(());
            } // drop write lock
        }
    }

    #[inline]
    fn url_from_path(&self, path: &str) -> String {
        format!("{}{COMMIT_BOOST_API}{path}", self.base_url)
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
            Err(CommitBoostError::NoSignature(
                "invalid data length".to_owned(),
            ))
        }?;

        let request = SignRequest::builder(
            SIGN_REQUEST_ID,
            *self.pubkeys.read().first().expect("pubkeys loaded"),
        )
        .with_root(root);

        let url = self.url_from_path(SIGN_REQUEST_PATH);

        tracing::debug!(url, ?request, "Requesting signature from commit_boost");

        let response = reqwest::Client::new()
            .post(url)
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        let response_bytes = response.bytes().await?;

        if !status.is_success() {
            let err = String::from_utf8_lossy(&response_bytes).into_owned();
            tracing::error!(err, "failed to get signature");
            return Err(eyre::eyre!(CommitBoostError::NoSignature(err)));
        }

        let sig = serde_json::from_slice(&response_bytes)?;
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use alloy_node_bindings::{Anvil, AnvilInstance};
    use alloy_primitives::{hex, Address, U256};
    use alloy_provider::network::{EthereumSigner, TransactionBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::SignerSync;
    use alloy_signer_wallet::LocalWallet;
    use ssz_rs::HashTreeRoot;

    use crate::primitives::{ConstraintsMessage, InclusionRequest};

    use super::*;

    fn launch_anvil() -> AnvilInstance {
        Anvil::new().block_time(1).chain_id(1337).spawn()
    }

    #[tokio::test]
    async fn test_commit_boost_signature() {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();

        let wallet: LocalWallet = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let client = CommitBoostClient::new("http://localhost:33950")
            .await
            .unwrap();

        let tx_request = default_transaction(sender);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumSigner = wallet.into();
        let signed = tx_request.build(&signer).await.unwrap();

        let req = InclusionRequest {
            slot: 20,
            tx: signed,
            signature: sig,
        };

        let message = ConstraintsMessage::build(0, 0, req).unwrap();
        let root = message.hash_tree_root().unwrap();
        let signature = client.sign(root.as_ref()).await.unwrap();

        println!("Message signed, signature: {signature}")
        // assert!(signature.verify(&message.hash_tree_root(), &client.pubkeys.first().unwrap()));
    }

    fn default_transaction(sender: Address) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(sender)
            // Burn it
            .with_to(Address::random())
            .with_chain_id(1337)
            .with_nonce(0)
            .with_value(U256::from(100))
            .with_gas_limit(21_000)
            .with_max_priority_fee_per_gas(1_000_000_000)
            .with_max_fee_per_gas(20_000_000_000)
    }
}
