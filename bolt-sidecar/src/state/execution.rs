use alloy_eips::eip4844::MAX_BLOBS_PER_BLOCK;
use alloy_primitives::{Address, SignatureError};
use reth_primitives::{transaction::TxType, TransactionSigned};
use std::collections::HashMap;
use thiserror::Error;

use crate::{
    builder::BlockTemplate,
    common::{calculate_max_basefee, validate_transaction},
    primitives::{AccountState, ChainHead, CommitmentRequest, Slot},
};

use super::{fetcher::StateFetcher, StateError};

/// Possible commitment validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// The transaction fee is too low to cover the maximum base fee.
    #[error("Transaction fee is too low, need {0} gwei to cover the maximum base fee")]
    BaseFeeTooLow(u128),
    /// The transaction nonce is too low.
    #[error("Transaction nonce too low")]
    NonceTooLow,
    /// The transaction nonce is too high.
    #[error("Transaction nonce too high")]
    NonceTooHigh,
    /// The sender does not have enough balance to pay for the transaction.
    #[error("Not enough balance to pay for value + maximum fee")]
    InsufficientBalance,
    /// There are too many EIP-4844 transactions in the target block.
    #[error("Too many EIP-4844 transactions in target block")]
    Eip4844Limit,
    /// The signature is invalid.
    #[error("Signature error: {0:?}")]
    Signature(#[from] SignatureError),
    /// Could not recover signature,
    #[error("Could not recover signer")]
    RecoverSigner,
    /// NOTE: this should not be exposed to the user.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl ValidationError {
    /// Returns true if the error is internal.
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
#[derive(Debug)]
pub struct ExecutionState<C> {
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
    block_templates: HashMap<Slot, BlockTemplate>,

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

    /// Returns the current base fee in gwei
    pub fn basefee(&self) -> u128 {
        self.basefee
    }

    /// Returns the current block templates mapped by slot number
    pub fn block_templates(&self) -> &HashMap<u64, BlockTemplate> {
        &self.block_templates
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
        let CommitmentRequest::Inclusion(req) = request;

        let sender = req.tx.recover_signer().ok_or(ValidationError::Internal(
            "Failed to recover signer from transaction".to_string(),
        ))?;

        tracing::debug!(%sender, target_slot = req.slot, "Trying to commit inclusion request to block template");

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
            validate_transaction(&account_state, &req.tx)?;
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
            validate_transaction(&account_state, &req.tx)?;
        }

        // Check EIP-4844-specific limits
        if req.tx.tx_type() == TxType::Eip4844 {
            if let Some(template) = self.block_templates.get(&req.slot) {
                if template.blob_count() >= MAX_BLOBS_PER_BLOCK {
                    return Err(ValidationError::Eip4844Limit);
                }
            }

            // TODO: check max_fee_per_blob_gas against the blob_base_fee
        }

        self.commit_transaction(req.slot, req.tx.clone());

        Ok(())
    }

    /// Commits the transaction to the target block. Initializes a new block template
    /// if one does not exist for said block number.
    /// TODO: remove `pub` modifier once `try_commit` is fully implemented.
    pub fn commit_transaction(&mut self, target_slot: u64, transaction: TransactionSigned) {
        if let Some(template) = self.block_templates.get_mut(&target_slot) {
            template.add_transaction(transaction);
        } else {
            let mut template = BlockTemplate::default();
            template.add_transaction(transaction);
            self.block_templates.insert(target_slot, template);
        }
    }

    /// Updates the state with a new head
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
    /// This should be called when we need to propose a block for the given slot.
    pub fn get_block_template(&mut self, slot: u64) -> Option<BlockTemplate> {
        self.block_templates.remove(&slot)
    }
}

#[derive(Debug, Clone)]
pub struct StateUpdate {
    pub account_states: HashMap<Address, AccountState>,
    pub min_basefee: u128,
}

fn reject_internal(reason: &str) -> ValidationError {
    ValidationError::Internal(reason.to_string())
}
