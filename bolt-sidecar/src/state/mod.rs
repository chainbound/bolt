//! The `state` module is responsible for keeping a local copy of relevant state that is needed
//! to simulate commitments against. It is updated on every block. It has both execution state and consensus state.

use alloy_transport::TransportError;
use thiserror::Error;

mod execution;
pub use execution::{ExecutionState, ValidationError};

/// Module to fetch state from the Execution layer.
pub mod fetcher;

pub mod consensus;
pub use consensus::ConsensusState;

/// Module to track the head of the chain.
pub mod head_tracker;

/// Errors that can occur in the state module.
#[derive(Debug, Error)]
pub enum StateError {
    /// An error occurred while fetching from an RPC client.
    #[error("RPC error: {0:?}")]
    Rpc(#[from] TransportError),
}

#[cfg(test)]
mod tests {
    use alloy_consensus::constants::ETH_TO_WEI;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_network::EthereumWallet;
    use alloy_primitives::{hex, uint, Uint};
    use alloy_provider::{network::TransactionBuilder, Provider, ProviderBuilder};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use execution::{ExecutionState, ValidationError};
    use fetcher::StateClient;
    use tracing_subscriber::fmt;

    use crate::{
        primitives::{ChainHead, CommitmentRequest, InclusionRequest},
        test_util::{default_test_transaction, launch_anvil},
    };

    use super::*;

    #[tokio::test]
    async fn test_valid_inclusion_request() {
        let _ = fmt::try_init();

        // let mut state = State::new(get_client()).await.unwrap();
        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint(), 1);

        let head = ChainHead::new(1, 0);

        let mut state = ExecutionState::new(client, head).await.unwrap();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: signed,
            signature: sig,
        });

        assert!(state.try_commit(&request).await.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_nonce() {
        let _ = fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint(), 1);

        let head = ChainHead::new(1, 0);

        let mut state = ExecutionState::new(client, head).await.unwrap();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender).with_nonce(1);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: signed,
            signature: sig,
        });

        assert!(matches!(
            state.try_commit(&request).await,
            Err(ValidationError::NonceTooHigh)
        ));
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_balance() {
        let _ = fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint(), 1);

        let head = ChainHead::new(1, 0);

        let mut state = ExecutionState::new(client, head).await.unwrap();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender)
            .with_value(uint!(11_000_U256 * Uint::from(ETH_TO_WEI)));

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: signed,
            signature: sig,
        });

        assert!(matches!(
            state.try_commit(&request).await,
            Err(ValidationError::InsufficientBalance)
        ));
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_basefee() {
        let _ = fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint(), 1);

        let head = ChainHead::new(1, 0);

        let mut state = ExecutionState::new(client, head).await.unwrap();

        let basefee = state.basefee();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender).with_max_fee_per_gas(basefee - 1);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: signed,
            signature: sig,
        });

        assert!(matches!(
            state.try_commit(&request).await,
            Err(ValidationError::BaseFeeTooLow(_))
        ));
    }

    #[tokio::test]
    async fn test_invalidate_inclusion_request() {
        let _ = fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint(), 1);

        let head = ChainHead::new(1, 0);

        let mut state = ExecutionState::new(client, head).await.unwrap();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: signed.clone(),
            signature: sig,
        });

        assert!(state.try_commit(&request).await.is_ok());
        assert!(state.block_templates().get(&10).unwrap().transactions_len() == 1);

        let provider = ProviderBuilder::new().on_http(anvil.endpoint_url());

        let notif = provider
            .send_raw_transaction(&signed.encoded_2718())
            .await
            .unwrap();

        // Wait for confirmation
        let receipt = notif.get_receipt().await.unwrap();

        let new_head = ChainHead::new(2, receipt.block_number.unwrap());

        // Update the head, which should invalidate the transaction due to a nonce conflict
        state.update_head(new_head).await.unwrap();

        let transactions_len = state.block_templates().get(&10).unwrap().transactions_len();
        assert!(transactions_len == 0);
    }
}
