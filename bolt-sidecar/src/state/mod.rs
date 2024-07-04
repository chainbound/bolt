//! The `state` module is responsible for keeping a local copy of relevant state that is needed
//! to simulate commitments against. It is updated on every block. It has both execution state and consensus state.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{future::poll_fn, Future, FutureExt};
use tokio::time::Sleep;

mod execution;
pub use execution::{ExecutionState, ValidationError};

/// Module to fetch state from the Execution layer.
pub mod fetcher;
pub use fetcher::StateClient;

pub mod consensus;
pub use consensus::ConsensusState;

/// Module to track the head of the chain.
pub mod head_tracker;
pub use head_tracker::HeadTracker;

/// The deadline for a which a commitment is considered valid.
#[derive(Debug)]
pub struct CommitmentDeadline {
    slot: u64,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl CommitmentDeadline {
    /// Create a new deadline for a given slot and duration.
    pub fn new(slot: u64, duration: Duration) -> Self {
        let sleep = Some(Box::pin(tokio::time::sleep(duration)));
        Self { slot, sleep }
    }

    /// Poll the deadline until it is reached.
    pub async fn wait(&mut self) -> Option<u64> {
        let slot = poll_fn(|cx| self.poll_unpin(cx)).await;
        self.sleep = None;
        slot
    }
}

/// Poll the deadline until it is reached.
///
/// - If already reached, the future will return `None` immediately.
/// - If not reached, the future will return `Some(slot)` when the deadline is reached.
impl Future for CommitmentDeadline {
    type Output = Option<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(ref mut sleep) = self.sleep else {
            return Poll::Ready(None);
        };

        match sleep.as_mut().poll(cx) {
            Poll::Ready(_) => Poll::Ready(Some(self.slot)),
            Poll::Pending => Poll::Pending,
        }
    }
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
    use reth_primitives::TransactionSigned;
    use tracing_subscriber::fmt;

    use crate::{
        primitives::{CommitmentRequest, InclusionRequest},
        test_util::{default_test_transaction, launch_anvil},
    };

    use super::*;

    #[tokio::test]
    async fn test_commitment_deadline() {
        let time = std::time::Instant::now();
        let mut deadline = CommitmentDeadline::new(0, Duration::from_secs(1));

        let slot = deadline.wait().await;
        println!("Deadline reached. Passed {:?}", time.elapsed());
        assert_eq!(slot, Some(0));

        let time = std::time::Instant::now();
        let slot = deadline.wait().await;
        println!("Deadline reached. Passed {:?}", time.elapsed());
        assert_eq!(slot, None);
    }

    #[tokio::test]
    async fn test_valid_inclusion_request() {
        let _ = fmt::try_init();

        // let mut state = State::new(get_client()).await.unwrap();
        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint());

        let mut state = ExecutionState::new(client).await.unwrap();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender, None);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        // Trick to parse into the TransactionSigned type
        let tx_signed_bytes = signed.encoded_2718();
        let tx_signed =
            TransactionSigned::decode_enveloped(&mut tx_signed_bytes.as_slice()).unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: tx_signed,
            signature: sig,
        });

        assert!(state.try_commit(&request).await.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_nonce() {
        let _ = fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint());

        let mut state = ExecutionState::new(client).await.unwrap();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender, Some(1));

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        // Trick to parse into the TransactionSigned type
        let tx_signed_bytes = signed.encoded_2718();
        let tx_signed =
            TransactionSigned::decode_enveloped(&mut tx_signed_bytes.as_slice()).unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: tx_signed,
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
        let client = StateClient::new(&anvil.endpoint());

        let mut state = ExecutionState::new(client).await.unwrap();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender, None)
            .with_value(uint!(11_000_U256 * Uint::from(ETH_TO_WEI)));

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        // Trick to parse into the TransactionSigned type
        let tx_signed_bytes = signed.encoded_2718();
        let tx_signed =
            TransactionSigned::decode_enveloped(&mut tx_signed_bytes.as_slice()).unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: tx_signed,
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
        let client = StateClient::new(&anvil.endpoint());

        let mut state = ExecutionState::new(client).await.unwrap();

        let basefee = state.basefee();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender, None).with_max_fee_per_gas(basefee - 1);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        // Trick to parse into the TransactionSigned type
        let tx_signed_bytes = signed.encoded_2718();
        let tx_signed =
            TransactionSigned::decode_enveloped(&mut tx_signed_bytes.as_slice()).unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: tx_signed,
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
        let client = StateClient::new(&anvil.endpoint());

        let mut state = ExecutionState::new(client).await.unwrap();

        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_test_transaction(sender, None);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumWallet = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        // Trick to parse into the TransactionSigned type
        let tx_signed_bytes = signed.encoded_2718();
        let tx_signed =
            TransactionSigned::decode_enveloped(&mut tx_signed_bytes.as_slice()).unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            tx: tx_signed,
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

        // Update the head, which should invalidate the transaction due to a nonce conflict
        state.update_head(receipt.block_number).await.unwrap();

        let transactions_len = state.block_templates().get(&10).unwrap().transactions_len();
        assert!(transactions_len == 0);
    }
}
