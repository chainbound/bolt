//! The `state` module is responsible for keeping a local copy of relevant state that is needed
//! to simulate commitments against. It is updated on every block.
use alloy_primitives::Address;
use alloy_rpc_types::Transaction;
use alloy_transport::TransportError;
use std::collections::HashMap;
use thiserror::Error;

use crate::{
    common::{calculate_max_basefee, validate_transaction},
    template::BlockTemplate,
    types::{commitment::CommitmentRequest, AccountState},
};

mod fetcher;
use fetcher::StateFetcher;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("RPC error: {0:?}")]
    Rpc(#[from] TransportError),
}

/// Possible commitment validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Slot too low: {0}")]
    SlotTooLow(u64),
    #[error("Transaction fee is too low, need {0} gwei to cover the maximum base fee")]
    FeeTooLow(u128),
    #[error("Transaction nonce too low")]
    NonceTooLow,
    #[error("Transaction nonce too high")]
    NonceTooHigh,
    #[error("Not enough balance to pay for value + maximum fee")]
    InsufficientBalance,
    /// NOTE: this should not be exposed to the user.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// The minimal state of the chain at some block number (`head`).
/// This is the state that is needed to simulate commitments.
/// It contains per-address nonces and balances, as well as the minimum basefee.
/// It also contains the block template which can be used
///
/// # Updating
/// The state can be updated with a new head block number. This will fetch the state
/// update from the client and apply it to the state.
struct State<C> {
    /// The latest head block number.
    head: u64,

    /// The base fee at the head block.
    basefee: u128,
    /// The cached account states.
    account_states: HashMap<Address, AccountState>,

    /// The optional block template.
    block_template: Option<BlockTemplate>,

    /// The state fetcher client.
    client: C,
}

impl<C: StateFetcher> State<C> {
    /// Creates a new state with the given client. Initializes the `head` and `basefee` fields
    /// with the current head and basefee.
    pub async fn new(client: C) -> Result<Self, StateError> {
        let (head, basefee) = tokio::try_join!(client.get_head(), client.get_basefee())?;

        Ok(Self {
            head,
            basefee,
            account_states: HashMap::new(),
            block_template: None,
            client,
        })
    }

    /// Validates the commitment request against state (historical + intermediate).
    /// NOTE: This function only simulates against execution state, it does not consider
    /// timing or proposer slot targets.
    ///
    /// If the commitment is invalid
    /// because of nonce, basefee or balance errors, it will return an error.
    /// If the commitment is valid, it will be added to the block template and its account state
    /// will be cached. If this is succesful, any callers can be sure that the commitment is valid
    /// and can sign it.
    pub async fn try_commit(&mut self, request: &CommitmentRequest) -> Result<(), ValidationError> {
        // TODO: more pre-checks
        // - Check if the target slot is actually our proposer slot
        // - Check how far into the slot we currently are

        let CommitmentRequest::Inclusion(req) = request;

        let sender = req.transaction.from;

        // TODO: for now, we don't accept same-slot inclusion requests.
        // In the future, we can do this (up to a certain deadline like 6s-8s)
        if req.slot <= self.head {
            return Err(ValidationError::SlotTooLow(req.slot));
        }

        // Check if the max_fee_per_gas would cover the maximum possible basefee.
        let slot_diff = req.slot - self.head;

        // Calculate the max possible basefee given the slot diff
        let max_basefee = calculate_max_basefee(self.basefee, slot_diff)
            .ok_or(reject_internal("Overflow calculating max basefee"))?;

        // Validate the base fee
        if !req.validate_basefee(max_basefee) {
            return Err(ValidationError::FeeTooLow(max_basefee as u128));
        }

        // If we have the account state, use it here
        if let Some(account_state) = self.account_state(&sender) {
            // Validate the transaction against the account state
            validate_transaction(&account_state, &req.transaction)?;
        } else {
            // If we don't have the account state, we need to fetch it
            let account_state = self
                .client
                .get_account_state(&sender)
                .await
                .map_err(|e| reject_internal(&e.to_string()))?;

            self.account_states.insert(sender, account_state);

            // Validate the transaction against the account state
            validate_transaction(&account_state, &req.transaction)?;
        }

        // self.block_template.Ok(())
        Ok(())
    }

    // Updates the state with a new head
    pub async fn update(&mut self, block_number: u64) -> Result<(), StateError> {
        // TODO: invalidate any state that we don't need anymore (will be based on block template)
        let update = self
            .client
            .get_state_update(
                Some(block_number),
                self.account_states.keys().collect::<Vec<_>>(),
            )
            .await?;

        self.apply_state_update(block_number, update);

        Ok(())
    }

    /// Commits the transaction to the current block template. Initializes a new block template
    /// if one does not exist.
    fn commit_transaction_to_block(&mut self, transaction: Transaction) {
        if let Some(ref mut template) = self.block_template {
            template.add_transaction(transaction);
        } else {
            let mut template = BlockTemplate::new();
            template.add_transaction(transaction);
            self.block_template = Some(template);
        }
    }

    fn apply_state_update(&mut self, block_number: u64, update: StateUpdate) {
        self.head = block_number;
        self.basefee = update.min_basefee;

        // `extend` will overwrite existing values
        self.account_states.extend(update.account_states)
    }

    /// Returns the account state for the given address INCLUDING any intermediate block template state.
    fn account_state(&self, address: &Address) -> Option<AccountState> {
        let account_state = self.account_states.get(address).copied();

        if let Some(mut account_state) = account_state {
            if let Some(ref template) = self.block_template {
                // Apply the diffs from the block template
                if let Some((nonce_diff, balance_diff)) = template.state_diff().get_diff(address) {
                    // Nonce will always be increased
                    account_state.nonce += nonce_diff;
                    // Balance will always be decreased
                    account_state.balance -= balance_diff;
                }
            }

            Some(account_state)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
struct StateUpdate {
    account_states: HashMap<Address, AccountState>,
    min_basefee: u128,
}

fn reject_internal(reason: &str) -> ValidationError {
    ValidationError::Internal(reason.to_string())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_node_bindings::{Anvil, AnvilInstance};
    use alloy_primitives::U256;
    use alloy_provider::network::{EthereumSigner, TransactionBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer_wallet::LocalWallet;
    use fetcher::StateClient;

    use super::*;

    fn launch_anvil() -> AnvilInstance {
        Anvil::new().block_time(1).spawn()
    }

    #[tokio::test]
    async fn test_new_state() {
        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint(), 1);
        // Wait 2 seconds for Anvil to start up and append some blocks
        tokio::time::sleep(Duration::from_secs(2)).await;

        let state = State::new(client).await.unwrap();

        assert_ne!(state.head, 0);
        assert_ne!(state.basefee, 0);
    }

    #[tokio::test]
    async fn test_valid_inclusion_request() {
        // let mut state = State::new(get_client()).await.unwrap();
        let anvil = launch_anvil();
        let client = StateClient::new(&anvil.endpoint(), 1);

        let mut state = State::new(client).await.unwrap();

        let wallet: LocalWallet = anvil.keys()[0].clone().into();
        let signer: EthereumSigner = wallet.into();

        let sender = anvil.addresses()[0];

        let tx = TransactionRequest::default()
            .with_from(sender)
            // Burn it
            .with_to(Address::ZERO)
            .with_nonce(0)
            .with_chain_id(anvil.chain_id())
            .with_value(U256::from(100))
            .with_gas_limit(21_000)
            .with_max_priority_fee_per_gas(1_000_000_000)
            .with_max_fee_per_gas(20_000_000_000);

        let signed = tx.build(&signer).await.unwrap();
        todo!("finish this test")

        // let request = CommitmentRequest::Inclusion(InclusionRequest {
        //     slot: state.head + 1,
        //     transaction: signed.into(),
        //     signature: Default::default(),
        // });

        // state.try_commit()
    }
}
