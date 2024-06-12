use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use cb_common::pbs::{COMMIT_BOOST_API, PUBKEYS_PATH, SIGN_REQUEST_PATH};
use cb_crypto::types::SignRequest;
use ethereum_consensus::ssz::prelude::HashTreeRoot;
use thiserror::Error;

use crate::primitives::ConstraintsMessage;

const ID: &str = "bolt";

pub struct CommitBoostClient {
    url: String,
    client: reqwest::Client,
    pubkeys: Vec<BlsPublicKey>,
}

#[derive(Debug, Error)]
pub enum CommitBoostError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

impl CommitBoostClient {
    pub async fn new(url: impl Into<String>) -> Result<Self, CommitBoostError> {
        let mut client = Self {
            url: url.into(),
            client: reqwest::Client::new(),
            pubkeys: Vec::new(),
        };

        client.load_pubkeys().await?;

        Ok(client)
    }

    async fn load_pubkeys(&mut self) -> Result<(), CommitBoostError> {
        loop {
            let url = format!("{}{COMMIT_BOOST_API}{PUBKEYS_PATH}", self.url);

            tracing::debug!(url, "Loading signatures from commit_boost");

            let response = self.client.get(url).send().await?;
            let status = response.status();
            let response_bytes = response.bytes().await.expect("failed to get bytes");

            if !status.is_success() {
                let err = String::from_utf8_lossy(&response_bytes).into_owned();
                tracing::error!(err, ?status, "failed to get public keys");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            let pubkeys: Vec<BlsPublicKey> =
                serde_json::from_slice(&response_bytes).expect("failed deser");

            self.pubkeys = pubkeys;
        }
    }

    // TODO: error handling
    pub async fn sign_constraint(&self, constraint: &ConstraintsMessage) -> Option<BlsSignature> {
        let root = constraint.hash_tree_root().unwrap();
        let request = SignRequest::builder(ID, *self.pubkeys.first().expect("pubkeys loaded"))
            .with_root(root.into());

        let url = format!("{}{COMMIT_BOOST_API}{SIGN_REQUEST_PATH}", self.url);

        tracing::debug!(url, ?request, "Requesting signature from commit_boost");

        let response = reqwest::Client::new()
            .post(url)
            .json(&request)
            .send()
            .await
            .expect("failed to get request");

        let status = response.status();
        let response_bytes = response.bytes().await.expect("failed to get bytes");

        if !status.is_success() {
            let err = String::from_utf8_lossy(&response_bytes).into_owned();
            tracing::error!(err, "failed to get signature");
            return None;
        }

        serde_json::from_slice(&response_bytes).expect("failed deser")
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

    use crate::primitives::InclusionRequest;

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
        let signature = client.sign_constraint(&message).await.unwrap();

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
