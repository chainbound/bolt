use alloy_eips::eip4844::MAX_BLOBS_PER_BLOCK;
use alloy_primitives::{Address, SignatureError, U256};
use alloy_transport::TransportError;
use reth_primitives::{
    revm_primitives::EnvKzgSettings, BlobTransactionValidationError, PooledTransactionsElement,
};
use std::{collections::HashMap, num::NonZero};
use thiserror::Error;

use crate::{
    builder::BlockTemplate,
    common::{calculate_max_basefee, validate_transaction},
    primitives::{AccountState, CommitmentRequest, SignedConstraints, Slot, TransactionExt},
};

use super::fetcher::StateFetcher;

/// Possible commitment validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// The transaction fee is too low to cover the maximum base fee.
    #[error("Transaction fee is too low, need {0} gwei to cover the maximum basefee")]
    BaseFeeTooLow(u128),
    /// The transaction blob fee is too low to cover the maximum blob base fee.
    #[error("Transaction blob fee is too low, need {0} gwei to cover the maximum blob basefee")]
    BlobBaseFeeTooLow(u128),
    /// The transaction blob is invalid.
    #[error(transparent)]
    BlobValidation(#[from] BlobTransactionValidationError),
    /// The max basefee calculation incurred an overflow error.
    #[error("Invalid max basefee calculation: overflow")]
    MaxBaseFeeCalcOverflow,
    /// The transaction nonce is too low.
    #[error("Transaction nonce too low")]
    NonceTooLow,
    /// The transaction nonce is too high.
    #[error("Transaction nonce too high")]
    NonceTooHigh,
    /// The sender account is a smart contract and has code.
    #[error("Account has code")]
    AccountHasCode,
    /// The gas limit is too high.
    #[error("Gas limit too high")]
    GasLimitTooHigh,
    /// The transaction input size is too high.
    #[error("Transaction input size too high")]
    TransactionSizeTooHigh,
    /// Max priority fee per gas is greater than max fee per gas.
    #[error("Max priority fee per gas is greater than max fee per gas")]
    MaxPriorityFeePerGasTooHigh,
    /// The sender does not have enough balance to pay for the transaction.
    #[error("Not enough balance to pay for value + maximum fee")]
    InsufficientBalance,
    /// There are too many EIP-4844 transactions in the target block.
    #[error("Too many EIP-4844 transactions in target block")]
    Eip4844Limit,
    /// The maximum commitments have been reached for the slot.
    #[error("Max commitments reached for slot {0}: {1}")]
    MaxCommitmentsReachedForSlot(u64, usize),
    /// The signature is invalid.
    #[error("Signature error: {0:?}")]
    Signature(#[from] SignatureError),
    /// Could not recover signature,
    #[error("Could not recover signer")]
    RecoverSigner,
    /// The transaction chain ID does not match the expected chain ID.
    #[error("Chain ID mismatch")]
    ChainIdMismatch,
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
    /// The latest block number.
    block_number: u64,
    /// The latest slot number.
    slot: u64,
    /// The basefee at the head block.
    basefee: u128,
    /// The blob basefee at the head block.
    blob_basefee: u128,
    /// The cached account states. This should never be read directly.
    /// These only contain the canonical account states at the head block,
    /// not the intermediate states.
    account_states: HashMap<Address, AccountState>,
    /// The block templates by target SLOT NUMBER.
    /// We have multiple block templates because in rare cases we might have multiple
    /// proposal duties for a single lookahead.
    block_templates: HashMap<Slot, BlockTemplate>,
    /// The chain ID of the chain (constant).
    chain_id: u64,
    /// The maximum number of commitments per slot.
    max_commitments_per_slot: NonZero<usize>,
    /// The KZG settings for validating blobs.
    kzg_settings: EnvKzgSettings,
    /// The state fetcher client.
    client: C,
    /// Other values used for validation
    validation_params: ValidationParams,
}

/// Other values used for validation.
#[derive(Debug)]
pub struct ValidationParams {
    block_gas_limit: u64,
    max_tx_input_bytes: usize,
    max_init_code_byte_size: usize,
}

impl Default for ValidationParams {
    fn default() -> Self {
        Self {
            block_gas_limit: 30_000_000,
            max_tx_input_bytes: 4 * 32 * 1024,
            max_init_code_byte_size: 2 * 24576,
        }
    }
}

impl<C: StateFetcher> ExecutionState<C> {
    /// Creates a new state with the given client, initializing the
    /// basefee and head block number.
    pub async fn new(
        client: C,
        max_commitments_per_slot: NonZero<usize>,
    ) -> Result<Self, TransportError> {
        let (basefee, blob_basefee, block_number, chain_id) = tokio::try_join!(
            client.get_basefee(None),
            client.get_blob_basefee(None),
            client.get_head(),
            client.get_chain_id()
        )?;

        Ok(Self {
            basefee,
            blob_basefee,
            block_number,
            chain_id,
            max_commitments_per_slot,
            client,
            slot: 0,
            account_states: HashMap::new(),
            block_templates: HashMap::new(),
            // Load the default KZG settings
            kzg_settings: EnvKzgSettings::default(),
            // TODO: add a way to configure these values from CLI
            validation_params: ValidationParams::default(),
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
    ///
    /// NOTE: This function only simulates against execution state, it does not consider
    /// timing or proposer slot targets.
    ///
    /// If the commitment is invalid because of nonce, basefee or balance errors, it will return an error.
    /// If the commitment is valid, its account state
    /// will be cached. If this is succesful, any callers can be sure that the commitment is valid
    /// and SHOULD sign it and respond to the requester.
    ///
    /// TODO: should also validate everything in https://github.com/paradigmxyz/reth/blob/9aa44e1a90b262c472b14cd4df53264c649befc2/crates/transaction-pool/src/validate/eth.rs#L153
    pub async fn validate_commitment_request(
        &mut self,
        request: &CommitmentRequest,
    ) -> Result<Address, ValidationError> {
        let CommitmentRequest::Inclusion(req) = request;

        // Validate the chain ID
        if !req.validate_chain_id(self.chain_id) {
            return Err(ValidationError::ChainIdMismatch);
        }

        // Check if there is room for more commitments
        let template = self.get_block_template(req.slot);
        if let Some(template) = template {
            if template.transactions_len() >= self.max_commitments_per_slot.get() {
                return Err(ValidationError::MaxCommitmentsReachedForSlot(
                    self.slot,
                    self.max_commitments_per_slot.get(),
                ));
            }
        }

        // Check if the transaction size exceeds the maximum
        if req.tx.size() > self.validation_params.max_tx_input_bytes {
            return Err(ValidationError::TransactionSizeTooHigh);
        }

        // Check if the transaction is a contract creation and the init code size exceeds the maximum
        if req.tx.tx_kind().is_create()
            && req.tx.input().len() > self.validation_params.max_init_code_byte_size
        {
            return Err(ValidationError::TransactionSizeTooHigh);
        }

        // Check if the gas limit is higher than the maximum block gas limit
        if req.tx.gas_limit() > self.validation_params.block_gas_limit {
            return Err(ValidationError::GasLimitTooHigh);
        }

        // Ensure max_priority_fee_per_gas is less than max_fee_per_gas, if any
        if req
            .tx
            .max_priority_fee_per_gas()
            .is_some_and(|max_priority_fee| max_priority_fee > req.tx.max_fee_per_gas())
        {
            return Err(ValidationError::MaxPriorityFeePerGasTooHigh);
        }

        let sender = req.sender;

        tracing::debug!(%sender, target_slot = req.slot, "Trying to commit inclusion request to block template");

        // Check if the max_fee_per_gas would cover the maximum possible basefee.
        let slot_diff = req.slot.saturating_sub(self.slot);

        // Calculate the max possible basefee given the slot diff
        let max_basefee = calculate_max_basefee(self.basefee, slot_diff)
            .ok_or(ValidationError::MaxBaseFeeCalcOverflow)?;

        // Validate the base fee
        if !req.validate_basefee(max_basefee) {
            return Err(ValidationError::BaseFeeTooLow(max_basefee));
        }

        // Retrieve the nonce and balance diffs from previous preconfirmations for this slot.
        // If the template does not exist, or this is the first request for this sender,
        // its diffs will be zero.
        let (nonce_diff, balance_diff) = self
            .block_templates
            .get(&req.slot)
            .and_then(|template| template.state_diff().get_diff(&sender))
            // TODO: should balance diff be signed?
            .unwrap_or((0, U256::ZERO));

        let account_state = match self.account_state(&sender) {
            Some(account) => account,
            None => {
                let account = self
                    .client
                    .get_account_state(&sender, None)
                    .await
                    .map_err(|e| {
                        ValidationError::Internal(format!("Failed to fetch account state: {:?}", e))
                    })?;

                self.account_states.insert(sender, account);
                account
            }
        };

        let account_state_with_diffs = AccountState {
            transaction_count: account_state.transaction_count + nonce_diff,
            balance: account_state.balance - balance_diff,
            has_code: account_state.has_code,
        };

        // Validate the transaction against the account state with existing diffs
        validate_transaction(&account_state_with_diffs, &req.tx)?;

        // Check EIP-4844-specific limits
        if let Some(transaction) = req.tx.as_eip4844() {
            if let Some(template) = self.block_templates.get(&req.slot) {
                if template.blob_count() >= MAX_BLOBS_PER_BLOCK {
                    return Err(ValidationError::Eip4844Limit);
                }
            }

            let PooledTransactionsElement::BlobTransaction(ref blob_transaction) = req.tx else {
                unreachable!("EIP-4844 transaction should be a blob transaction")
            };

            // Calculate max possible increase in blob basefee
            let max_blob_basefee = calculate_max_basefee(self.blob_basefee, slot_diff)
                .ok_or(ValidationError::MaxBaseFeeCalcOverflow)?;

            if blob_transaction.transaction.max_fee_per_blob_gas < max_blob_basefee {
                return Err(ValidationError::BlobBaseFeeTooLow(max_blob_basefee));
            }

            // Validate blob against KZG settings
            transaction.validate_blob(&blob_transaction.sidecar, self.kzg_settings.get())?;
        }

        Ok(sender)
    }

    /// Commits the transaction to the target block. Initializes a new block template
    /// if one does not exist for said block number.
    /// TODO: remove `pub` modifier once `try_commit` is fully implemented.
    pub fn add_constraint(&mut self, target_slot: u64, signed_constraints: SignedConstraints) {
        if let Some(template) = self.block_templates.get_mut(&target_slot) {
            template.add_constraints(signed_constraints);
        } else {
            let mut template = BlockTemplate::default();
            template.add_constraints(signed_constraints);
            self.block_templates.insert(target_slot, template);
        }
    }

    /// Updates the state corresponding to the provided block number and slot.
    /// If the block number is not provided, the state will be updated to
    /// the latest head from the EL.
    pub async fn update_head(
        &mut self,
        block_number: Option<u64>,
        slot: u64,
    ) -> Result<(), TransportError> {
        self.slot = slot;

        let accounts = self.account_states.keys().collect::<Vec<_>>();
        let update = self.client.get_state_update(accounts, block_number).await?;

        self.apply_state_update(update);

        // Remove any block templates that are no longer valid
        self.block_templates.remove(&slot);

        Ok(())
    }

    fn apply_state_update(&mut self, update: StateUpdate) {
        // Update head and basefee
        self.block_number = update.block_number;
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
                // Retain only signed constraints where transactions are still valid based on the canonical account states.
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
    pub min_blob_basefee: u128,
    pub block_number: u64,
}
