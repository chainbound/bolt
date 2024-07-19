use std::{collections::HashMap, num::NonZero};

use alloy::{
    eips::eip4844::MAX_BLOBS_PER_BLOCK,
    primitives::{Address, SignatureError, U256},
    transports::TransportError,
};
use reth_primitives::{
    revm_primitives::EnvKzgSettings, BlobTransactionValidationError, PooledTransactionsElement,
};
use thiserror::Error;

use super::fetcher::StateFetcher;
use crate::{
    builder::BlockTemplate,
    common::{calculate_max_basefee, validate_transaction},
    primitives::{AccountState, CommitmentRequest, SignedConstraints, Slot, TransactionExt},
};

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
    #[error("Transaction nonce too low. Expected {0}, got {1}")]
    NonceTooLow(u64, u64),
    /// The transaction nonce is too high.
    #[error("Transaction nonce too high")]
    NonceTooHigh(u64, u64),
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
    #[error("Already requested a preconfirmation for slot {0}. Slot must be >= {0}")]
    SlotTooLow(u64),
    /// The maximum commitments have been reached for the slot.
    #[error("Max commitments reached for slot {0}: {1}")]
    MaxCommitmentsReachedForSlot(u64, usize),
    /// The maximum committed gas has been reached for the slot.
    #[error("Max committed gas reached for slot {0}: {1}")]
    MaxCommittedGasReachedForSlot(u64, u64),
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
    /// The maximum committed gas per slot.
    max_committed_gas_per_slot: NonZero<u64>,
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
        max_committed_gas_per_slot: NonZero<u64>,
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
            max_committed_gas_per_slot,
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

        let sender = req.sender;
        let target_slot = req.slot;

        // Validate the chain ID
        if !req.validate_chain_id(self.chain_id) {
            return Err(ValidationError::ChainIdMismatch);
        }

        let max_commitments_per_slot = self.max_commitments_per_slot.get();
        let max_committed_gas_per_slot = self.max_committed_gas_per_slot.get();

        // Check if there is room for more commitments and gas in the block template
        if let Some(template) = self.get_block_template(target_slot) {
            if template.transactions_len() >= max_commitments_per_slot {
                return Err(ValidationError::MaxCommitmentsReachedForSlot(
                    self.slot,
                    max_commitments_per_slot,
                ));
            }

            // Check if the committed gas exceeds the maximum
            if template.committed_gas().to::<u64>() >= max_committed_gas_per_slot {
                return Err(ValidationError::MaxCommittedGasReachedForSlot(
                    self.slot,
                    max_committed_gas_per_slot,
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

        tracing::debug!(%sender, target_slot, "Trying to commit inclusion request to block template");

        // Check if the max_fee_per_gas would cover the maximum possible basefee.
        let slot_diff = target_slot.saturating_sub(self.slot);

        // Calculate the max possible basefee given the slot diff
        let max_basefee = calculate_max_basefee(self.basefee, slot_diff)
            .ok_or(ValidationError::MaxBaseFeeCalcOverflow)?;

        // Validate the base fee
        if !req.validate_basefee(max_basefee) {
            return Err(ValidationError::BaseFeeTooLow(max_basefee));
        }

        // From previous preconfirmations requests retrieve
        // - the nonce difference from the account state.
        // - the balance difference from the account state.
        // - the highest slot number for which the user has requested a preconfirmation.
        //
        // If the templates do not exist, or this is the first request for this sender,
        // its diffs will be zero.
        let (nonce_diff, balance_diff, highest_slot) = self.block_templates.iter().fold(
            (0, U256::ZERO, 0),
            |(nonce_diff_acc, balance_diff_acc, highest_slot), (slot, block_template)| {
                let (nonce_diff, balance_diff, slot) = block_template
                    .get_diff(&sender)
                    .map(|(nonce, balance)| (nonce, balance, *slot))
                    .unwrap_or((0, U256::ZERO, 0));

                (
                    nonce_diff_acc + nonce_diff,
                    balance_diff_acc.saturating_add(balance_diff),
                    u64::max(highest_slot, slot),
                )
            },
        );

        if target_slot < highest_slot {
            return Err(ValidationError::SlotTooLow(highest_slot));
        }

        tracing::trace!(%sender, nonce_diff, %balance_diff, "Applying diffs to account state");

        let account_state = match self.account_state(&sender).copied() {
            Some(account) => account,
            None => {
                // Fetch the account state from the client if it does not exist
                let account = match self.client.get_account_state(&sender, None).await {
                    Ok(account) => account,
                    Err(err) => {
                        return Err(ValidationError::Internal(format!(
                            "Error fetching account state: {:?}",
                            err
                        )))
                    }
                };

                self.account_states.insert(sender, account);
                account
            }
        };

        let account_state_with_diffs = AccountState {
            transaction_count: account_state.transaction_count.saturating_add(nonce_diff),
            balance: account_state.balance.saturating_sub(balance_diff),
            has_code: account_state.has_code,
        };

        // Validate the transaction against the account state with existing diffs
        validate_transaction(&account_state_with_diffs, &req.tx)?;

        // Check EIP-4844-specific limits
        if let Some(transaction) = req.tx.as_eip4844() {
            if let Some(template) = self.block_templates.get(&target_slot) {
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
        self.remove_block_template(slot);

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
                if let Some((nonce_diff, balance_diff)) = template.get_diff(address) {
                    // Nonce will always be increased
                    account_state.transaction_count += nonce_diff;
                    // Balance will always be decreased
                    account_state.balance -= balance_diff;
                }
            }
        }
    }

    /// Returns the cached account state for the given address
    fn account_state(&self, address: &Address) -> Option<&AccountState> {
        self.account_states.get(address)
    }

    /// Gets the block template for the given slot number.
    pub fn get_block_template(&mut self, slot: u64) -> Option<&BlockTemplate> {
        self.block_templates.get(&slot)
    }

    /// Gets the block template for the given slot number and removes it from the cache.
    /// This should be called when we need to propose a block for the given slot,
    /// or when a new head comes in which makes an older block template useless.
    pub fn remove_block_template(&mut self, slot: u64) -> Option<BlockTemplate> {
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

#[cfg(test)]
mod tests {
    use crate::builder::template::StateDiff;
    use std::str::FromStr;
    use std::{num::NonZero, time::Duration};

    use alloy::{
        consensus::constants::ETH_TO_WEI,
        eips::eip2718::Encodable2718,
        network::EthereumWallet,
        primitives::{uint, Uint},
        providers::{network::TransactionBuilder, Provider, ProviderBuilder},
        signers::local::PrivateKeySigner,
    };
    use fetcher::{StateClient, StateFetcher};

    use crate::{
        crypto::{bls::Signer, SignableBLS, SignerBLS},
        primitives::{ConstraintsMessage, SignedConstraints},
        state::fetcher,
        test_util::{create_signed_commitment_request, default_test_transaction, launch_anvil},
    };

    use super::*;

    #[tokio::test]
    async fn test_valid_inclusion_request() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let max_gas = NonZero::new(10_000_000).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms, max_gas).await?;

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
    async fn test_invalid_inclusion_slot() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let max_gas = NonZero::new(10_000_000).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms, max_gas).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Create a transaction with a nonce that is too high
        let tx = default_test_transaction(*sender, Some(1));

        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;

        // Insert a constraint diff for slot 11
        let mut diffs = HashMap::new();
        diffs.insert(*sender, (1, U256::ZERO));
        state.block_templates.insert(
            11,
            BlockTemplate {
                state_diff: StateDiff { diffs },
                signed_constraints_list: vec![],
            },
        );

        assert!(matches!(
            state.validate_commitment_request(&request).await,
            Err(ValidationError::SlotTooLow(11))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_nonce() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let max_gas = NonZero::new(10_000_000).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms, max_gas).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Insert a constraint diff for slot 9 to simulate nonce increment
        let mut diffs = HashMap::new();
        diffs.insert(*sender, (1, U256::ZERO));
        state.block_templates.insert(
            9,
            BlockTemplate {
                state_diff: StateDiff { diffs },
                signed_constraints_list: vec![],
            },
        );

        // Create a transaction with a nonce that is too low
        let tx = default_test_transaction(*sender, Some(0));

        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;

        assert!(matches!(
            state.validate_commitment_request(&request).await,
            Err(ValidationError::NonceTooLow(1, 0))
        ));

        assert!(state.account_states.get(sender).unwrap().transaction_count == 0);

        // Create a transaction with a nonce that is too high
        let tx = default_test_transaction(*sender, Some(2));

        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;

        assert!(matches!(
            state.validate_commitment_request(&request).await,
            Err(ValidationError::NonceTooHigh(1, 2))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_balance() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let max_gas = NonZero::new(10_000_000).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms, max_gas).await?;

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
    async fn test_invalid_inclusion_request_balance_multiple() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let max_comms = NonZero::new(10).unwrap();
        let max_gas = NonZero::new(10_000_000).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms, max_gas).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = Signer::random();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Set the sender balance to just enough to pay for 1 transaction
        let balance = U256::from_str("500000000000000").unwrap(); // leave just 0.0005 ETH
        let sender_account = client.get_account_state(sender, None).await.unwrap();
        let balance_to_burn = sender_account.balance - balance;

        // burn the balance
        let tx = default_test_transaction(*sender, Some(0)).with_value(uint!(balance_to_burn));
        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;
        let tx_bytes = request
            .as_inclusion_request()
            .unwrap()
            .tx
            .envelope_encoded();
        let _ = client.inner().send_raw_transaction(tx_bytes).await?;

        // wait for the transaction to be included to update the sender balance
        tokio::time::sleep(Duration::from_secs(2)).await;
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // create a new transaction and request a preconfirmation for it
        let tx = default_test_transaction(*sender, Some(1));
        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;

        assert!(state.validate_commitment_request(&request).await.is_ok());

        let message = ConstraintsMessage::build(0, request.as_inclusion_request().unwrap().clone());
        let signature = signer.sign(&message.digest())?.to_string();
        let signed_constraints = SignedConstraints { message, signature };
        state.add_constraint(10, signed_constraints);

        // create a new transaction and request a preconfirmation for it
        let tx = default_test_transaction(*sender, Some(2));
        let request = create_signed_commitment_request(tx, sender_pk, 10).await?;

        // this should fail because the balance is insufficient as we spent
        // all of it on the previous preconfirmation
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
        let max_gas = NonZero::new(10_000_000).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms, max_gas).await?;

        let basefee = state.basefee();

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Create a transaction with a basefee that is too low
        let tx = default_test_transaction(*sender, None)
            .with_max_fee_per_gas(basefee - 1)
            .with_max_priority_fee_per_gas(basefee / 2);

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
        let max_gas = NonZero::new(10_000_000).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms, max_gas).await?;

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
        let max_gas = NonZero::new(10_000_000).unwrap();
        let mut state = ExecutionState::new(client.clone(), max_comms, max_gas).await?;

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
        // because it's now stale.
        state.update_head(None, target_slot).await?;

        assert!(state.get_block_template(target_slot).is_none());

        Ok(())
    }
}
