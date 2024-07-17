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

/// Module to track the consensus state.
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
    use std::num::NonZero;

    use alloy_consensus::constants::ETH_TO_WEI;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_network::EthereumWallet;
    use alloy_primitives::{uint, Uint};
    use alloy_provider::{network::TransactionBuilder, Provider, ProviderBuilder};
    use alloy_signer_local::PrivateKeySigner;
    use execution::{ExecutionState, ValidationError};
    use fetcher::{StateClient, StateFetcher};

    use crate::{
        crypto::{bls::Signer, SignableBLS, SignerBLS},
        primitives::{ConstraintsMessage, SignedConstraints},
        test_util::{create_signed_commitment_request, default_test_transaction, launch_anvil},
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
    async fn test_valid_inclusion_request() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx = default_test_transaction(*sender, None);

        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;

        assert!(state.validate_commitment_request(&request).await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_nonce() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Create a transaction with a nonce that is too high
        let tx = default_test_transaction(*sender, Some(1));

        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;

        assert!(matches!(
            state.validate_commitment_request(&request).await,
            Err(ValidationError::NonceTooHigh)
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_balance() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Create a transaction with a value that is too high
        let tx = default_test_transaction(*sender, None)
            .with_value(uint!(11_000_U256 * Uint::from(ETH_TO_WEI)));

        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;

        assert!(matches!(
            state.validate_commitment_request(&request).await,
            Err(ValidationError::InsufficientBalance)
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_basefee() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms).await?;

        let basefee = state.basefee();

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Create a transaction with a basefee that is too low
        let tx = default_test_transaction(*sender, None).with_max_fee_per_gas(basefee - 1);

        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;

        assert!(matches!(
            state.validate_commitment_request(&request).await,
            Err(ValidationError::BaseFeeTooLow(_))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalidate_inclusion_request() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());
        let provider = ProviderBuilder::new().on_http(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx = default_test_transaction(*sender, None);

        // build the signed transaction for submission later
        let wallet: PrivateKeySigner = anvil.keys()[0].clone().into();
        let signer: EthereumWallet = wallet.into();
        let signed = tx.clone().build(&signer).await?;

        let target_slot = 10;
        let request = create_signed_commitment_request(tx, sender_pk, target_slot).await?;
        let inclusion_request = request.as_inclusion_request().unwrap().clone();

        assert!(state.validate_commitment_request(&request).await.is_ok());

        let bls_signer = Signer::random();
        let message = ConstraintsMessage::build(0, inclusion_request);
        let signature = bls_signer.sign(&message.digest()).unwrap().to_string();
        let signed_constraints = SignedConstraints { message, signature };

        state.add_constraint(target_slot, signed_constraints);

        assert!(
            state
                .get_block_template(target_slot)
                .unwrap()
                .transactions_len()
                == 1
        );

        let notif = provider
            .send_raw_transaction(&signed.encoded_2718())
            .await?;

        // Wait for confirmation
        let receipt = notif.get_receipt().await?;

        // Update the head, which should invalidate the transaction due to a nonce conflict
        state
            .update_head(receipt.block_number, receipt.block_number.unwrap())
            .await?;

        let transactions_len = state
            .get_block_template(target_slot)
            .unwrap()
            .transactions_len();

        assert!(transactions_len == 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_invalidate_stale_template() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx = default_test_transaction(*sender, None);

        let target_slot = 10;
        let request = create_signed_commitment_request(tx, sender_pk, target_slot).await?;
        let inclusion_request = request.as_inclusion_request().unwrap().clone();

        assert!(state.validate_commitment_request(&request).await.is_ok());

        let bls_signer = Signer::random();
        let message = ConstraintsMessage::build(0, inclusion_request);
        let signature = bls_signer.sign(&message.digest()).unwrap().to_string();
        let signed_constraints = SignedConstraints { message, signature };

        state.add_constraint(target_slot, signed_constraints);

        assert!(
            state
                .get_block_template(target_slot)
                .unwrap()
                .transactions_len()
                == 1
        );

        // fast-forward the head to the target slot, which should invalidate the entire template
        // because it's now stale
        state.update_head(None, target_slot).await?;

        assert!(state.get_block_template(target_slot).is_none());

        Ok(())
    }
}
