//! The `state` module is responsible for keeping a local copy of relevant state that is needed
//! to simulate commitments against. It is updated on every block. It has both execution state and consensus state.
use alloy_transport::TransportError;
use std::sync::{atomic::AtomicU64, Arc};
use thiserror::Error;

mod execution;
pub use execution::ValidationError;
mod fetcher;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("RPC error: {0:?}")]
    Rpc(#[from] TransportError),
}

#[derive(Debug, Clone)]
struct ProposerDuties {
    assigned_slots: Vec<u64>,
}

#[derive(Debug, Clone)]
struct ChainHead {
    /// The current slot number.
    slot: Arc<AtomicU64>,
    /// The current block number.
    block: Arc<AtomicU64>,
}

impl ChainHead {
    pub fn new(slot: u64, head: u64) -> Self {
        Self {
            slot: Arc::new(AtomicU64::new(slot)),
            block: Arc::new(AtomicU64::new(head)),
        }
    }

    /// Get the slot number (consensus layer).
    pub fn slot(&self) -> u64 {
        self.slot.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get the block number (execution layer).
    pub fn block(&self) -> u64 {
        self.block.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::constants::ETH_TO_WEI;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_node_bindings::{Anvil, AnvilInstance};
    use alloy_primitives::{hex, uint, Address, Uint, U256};
    use alloy_provider::{
        network::{EthereumSigner, TransactionBuilder},
        Provider, ProviderBuilder,
    };
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::SignerSync;
    use alloy_signer_wallet::LocalWallet;
    use execution::{ExecutionState, ValidationError};
    use fetcher::StateClient;
    use tracing_subscriber::fmt;

    use crate::primitives::{CommitmentRequest, InclusionRequest};

    use super::*;

    fn launch_anvil() -> AnvilInstance {
        Anvil::new().block_time(1).chain_id(1337).spawn()
    }

    fn default_transaction(sender: Address) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(sender)
            // Burn it
            .with_to(Address::ZERO)
            .with_chain_id(1337)
            .with_nonce(0)
            .with_value(U256::from(100))
            .with_gas_limit(21_000)
            .with_max_priority_fee_per_gas(1_000_000_000)
            .with_max_fee_per_gas(20_000_000_000)
    }

    #[tokio::test]
    async fn test_valid_inclusion_request() {
        let _ = fmt::try_init();

        // let mut state = State::new(get_client()).await.unwrap();
        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint(), 1);

        let head = ChainHead::new(1, 0);

        let mut state = ExecutionState::new(client, head).await.unwrap();

        let wallet: LocalWallet = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_transaction(sender);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumSigner = wallet.into();
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

        let wallet: LocalWallet = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_transaction(sender).with_nonce(1);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumSigner = wallet.into();
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

        let wallet: LocalWallet = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx =
            default_transaction(sender).with_value(uint!(11_000_U256 * Uint::from(ETH_TO_WEI)));

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumSigner = wallet.into();
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

        let wallet: LocalWallet = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_transaction(sender).with_max_fee_per_gas(basefee - 1);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumSigner = wallet.into();
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

        let wallet: LocalWallet = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_transaction(sender);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumSigner = wallet.into();
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
