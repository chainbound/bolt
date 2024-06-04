//! The `state` module is responsible for keeping a local copy of relevant state that is needed
//! to simulate commitments against. It is updated on every block. It has both execution state and consensus state.
use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, SignatureError};
use alloy_transport::TransportError;
use std::{
    collections::HashMap,
    sync::{atomic::AtomicU64, Arc},
};
use thiserror::Error;

use crate::{
    common::{calculate_max_basefee, validate_transaction},
    template::BlockTemplate,
    types::{commitment::CommitmentRequest, transaction::TxInfo, AccountState},
};

mod fetcher;
use fetcher::StateFetcher;

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

/// Possible commitment validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Transaction fee is too low, need {0} gwei to cover the maximum base fee")]
    BaseFeeTooLow(u128),
    #[error("Transaction nonce too low")]
    NonceTooLow,
    #[error("Transaction nonce too high")]
    NonceTooHigh,
    #[error("Not enough balance to pay for value + maximum fee")]
    InsufficientBalance,
    #[error("Signature error: {0:?}")]
    Signature(#[from] SignatureError),
    /// NOTE: this should not be exposed to the user.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl ValidationError {
    pub fn is_internal(&self) -> bool {
        matches!(self, Self::Internal(_))
    }
}

/// The minimal state of the execution layer at some block number (`head`).
/// This is the state that is needed to simulate commitments.
/// It contains per-address nonces and balances, as well as the minimum basefee.
/// It also contains the block template which can be used to simulate new commitments
/// and as a fallback block in case of faults.
///
/// # Updating & Invalidation
/// The state can be updated with a new head block number. This will fetch the state
/// update from the client and apply it to the state. It will also invalidate any commitments
/// that conflict with the new state so that we NEVER propose an invalid block.
struct ExecutionState<C> {
    /// The latest head block number.
    head: ChainHead,

    /// The base fee at the head block.
    basefee: u128,
    /// The cached account states. This should never be read directly.
    /// These only contain the canonical account states at the head block,
    /// not the intermediate states.
    account_states: HashMap<Address, AccountState>,

    /// The block templates by target SLOT NUMBER.
    /// We have multiple block templates because in rare cases we might have multiple
    /// proposal duties for a single lookahead.
    block_templates: HashMap<u64, BlockTemplate>,

    /// The state fetcher client.
    client: C,
}

impl<C: StateFetcher> ExecutionState<C> {
    /// Creates a new state with the given client. Initializes the `head` and `basefee` fields
    /// with the current head and basefee.
    pub async fn new(client: C, head: ChainHead) -> Result<Self, StateError> {
        let basefee = client.get_basefee(Some(head.block())).await?;

        Ok(Self {
            head,
            basefee,
            account_states: HashMap::new(),
            block_templates: HashMap::new(),
            client,
        })
    }

    /// Validates the commitment request against state (historical + intermediate).
    /// NOTE: This function only simulates against execution state, it does not consider
    /// timing or proposer slot targets.
    ///
    /// If the commitment is invalid because of nonce, basefee or balance errors, it will return an error.
    /// If the commitment is valid, it will be added to the block template and its account state
    /// will be cached. If this is succesful, any callers can be sure that the commitment is valid
    /// and SHOULD sign it and respond to the requester.
    pub async fn try_commit(&mut self, request: &CommitmentRequest) -> Result<(), ValidationError> {
        // TODO: more pre-checks
        // - Check if the target slot is actually our proposer slot
        // - Check how far into the slot we currently are

        let CommitmentRequest::Inclusion(req) = request;

        let sender = req.transaction.from()?;

        // Check if the max_fee_per_gas would cover the maximum possible basefee.
        let slot_diff = req.slot - self.head.slot();

        // Calculate the max possible basefee given the slot diff
        let max_basefee = calculate_max_basefee(self.basefee, slot_diff)
            .ok_or(reject_internal("Overflow calculating max basefee"))?;

        // Validate the base fee
        if !req.validate_basefee(max_basefee) {
            return Err(ValidationError::BaseFeeTooLow(max_basefee as u128));
        }

        // If we have the account state, use it here
        if let Some(account_state) = self.account_state(&sender) {
            // Validate the transaction against the account state
            tracing::debug!(address = %sender, "Known account state: {account_state:?}");
            validate_transaction(&account_state, &req.transaction)?;
        } else {
            tracing::debug!(address = %sender, "Unknown account state");
            // If we don't have the account state, we need to fetch it
            let account_state = self
                .client
                .get_account_state(&sender, None)
                .await
                .map_err(|e| reject_internal(&e.to_string()))?;

            tracing::debug!(address = %sender, "Fetched account state: {account_state:?}");

            // Record the account state for later
            self.account_states.insert(sender, account_state);

            // Validate the transaction against the account state
            validate_transaction(&account_state, &req.transaction)?;
        }

        self.commit_transaction(req.slot, req.transaction.clone());

        Ok(())
    }

    /// Commits the transaction to the target block. Initializes a new block template
    /// if one does not exist for said block number.
    fn commit_transaction(&mut self, target_slot: u64, transaction: TxEnvelope) {
        if let Some(template) = self.block_templates.get_mut(&target_slot) {
            template.add_transaction(transaction);
        } else {
            let mut template = BlockTemplate::new();
            template.add_transaction(transaction);
            self.block_templates.insert(target_slot, template);
        }
    }

    // Updates the state with a new head
    pub async fn update_head(&mut self, head: ChainHead) -> Result<(), StateError> {
        // TODO: invalidate any state that we don't need anymore (will be based on block template)
        let update = self
            .client
            .get_state_update(
                self.account_states.keys().collect::<Vec<_>>(),
                Some(head.block()),
            )
            .await?;

        self.apply_state_update(head, update);

        Ok(())
    }

    fn apply_state_update(&mut self, head: ChainHead, update: StateUpdate) {
        // Update head and basefee
        self.head = head;
        self.basefee = update.min_basefee;

        // `extend` will overwrite existing values. This is what we want.
        self.account_states.extend(update.account_states);

        self.refresh_templates();
    }

    /// Refreshes the block templates with the latest account states and removes any invalid transactions by checking
    /// the nonce and balance of the account after applying the state diffs.
    fn refresh_templates(&mut self) {
        for (address, account_state) in self.account_states.iter_mut() {
            tracing::trace!(%address, ?account_state, "Refreshing template...");
            // Iterate over all block templates and apply the state diff
            for (_, template) in self.block_templates.iter_mut() {
                // Retain only the transactions that are still valid based on the canonical account states.
                template.retain(*address, *account_state);

                // Update the account state with the remaining state diff for the next iteration.
                if let Some((nonce_diff, balance_diff)) = template.state_diff().get_diff(address) {
                    // Nonce will always be increased
                    account_state.transaction_count += nonce_diff;
                    // Balance will always be decreased
                    account_state.balance -= balance_diff;
                }
            }
        }
    }

    /// Returns the account state for the given address INCLUDING any intermediate block templates state.
    fn account_state(&self, address: &Address) -> Option<AccountState> {
        let account_state = self.account_states.get(address).copied();

        if let Some(mut account_state) = account_state {
            // Iterate over all block templates and apply the state diff
            for (_, template) in self.block_templates.iter() {
                if let Some((nonce_diff, balance_diff)) = template.state_diff().get_diff(address) {
                    // Nonce will always be increased
                    account_state.transaction_count += nonce_diff;
                    // Balance will always be decreased
                    account_state.balance -= balance_diff;
                }
            }

            Some(account_state)
        } else {
            None
        }
    }

    /// Gets the block template for the given slot number and removes it from the cache.
    pub fn get_block_template(&mut self, slot: u64) -> Option<BlockTemplate> {
        self.block_templates.remove(&slot)
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
    use alloy_consensus::constants::ETH_TO_WEI;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_node_bindings::{Anvil, AnvilInstance};
    use alloy_primitives::{hex, uint, Uint, U256};
    use alloy_provider::{
        network::{EthereumSigner, TransactionBuilder},
        Provider, ProviderBuilder,
    };
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::SignerSync;
    use alloy_signer_wallet::LocalWallet;
    use fetcher::StateClient;
    use tracing_subscriber::fmt;

    use crate::types::commitment::InclusionRequest;

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
            transaction: signed,
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
            transaction: signed,
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
            transaction: signed,
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

        let basefee = state.basefee;

        let wallet: LocalWallet = anvil.keys()[0].clone().into();

        let sender = anvil.addresses()[0];

        let tx = default_transaction(sender).with_max_fee_per_gas(basefee - 1);

        let sig = wallet.sign_message_sync(&hex!("abcd")).unwrap();

        let signer: EthereumSigner = wallet.into();
        let signed = tx.build(&signer).await.unwrap();

        let request = CommitmentRequest::Inclusion(InclusionRequest {
            slot: 10,
            transaction: signed,
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
            transaction: signed.clone(),
            signature: sig,
        });

        assert!(state.try_commit(&request).await.is_ok());
        assert!(state.block_templates.get(&10).unwrap().transactions_len() == 1);

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

        let transactions_len = state.block_templates.get(&10).unwrap().transactions_len();
        assert!(transactions_len == 0);
    }
}
