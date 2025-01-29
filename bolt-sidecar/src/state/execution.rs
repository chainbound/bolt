use alloy::{
    consensus::{BlobTransactionValidationError, EnvKzgSettings, Transaction},
    eips::eip4844::MAX_BLOBS_PER_BLOCK,
    primitives::{Address, U256},
    transports::TransportError,
};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

use crate::{
    builder::template::BlockTemplate,
    common::{
        score_cache::ScoreCache,
        transactions::{calculate_max_basefee, max_transaction_cost, validate_transaction},
    },
    config::limits::LimitsOpts,
    primitives::{
        diffs::{AccountDiff, BalanceDiff, BalanceDiffApplier},
        signature::SignatureError,
        AccountState, InclusionRequest, SignedConstraints, Slot,
    },
    state::pricing,
    telemetry::ApiMetrics,
};

use super::{account_state::AccountStateCache, fetcher::StateFetcher, InclusionPricer};

/// Possible commitment validation errors.
///
/// NOTE: `Clone` not implementable due to `BlobTransactionValidationError`
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
    #[error("Transaction nonce too high. Expected {0}, got {1}")]
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
    /// Max priority fee per gas is less than min priority fee.
    #[error("Max priority fee per gas {0} is less than min priority fee {1}")]
    MaxPriorityFeePerGasTooLow(u128, u128),
    /// The sender does not have enough balance to pay for the transaction.
    #[error("Not enough balance to pay for value + maximum fee")]
    InsufficientBalance,
    /// Pricing calculation error.
    #[error("Pricing calculation error: {0}")]
    Pricing(#[from] pricing::PricingError),
    /// There are too many EIP-4844 transactions in the target block.
    #[error("Too many EIP-4844 transactions in target block")]
    Eip4844Limit,
    /// The maximum commitments have been reached for the slot.
    #[error("Already requested a preconfirmation for slot {0}. Slot must be >= {0}")]
    SlotTooLow(u64),
    /// The maximum committed gas has been reached for the slot.
    #[error("Max committed gas reached for slot {0}: {1}")]
    MaxCommittedGasReachedForSlot(u64, u64),
    /// The signature is invalid.
    #[error("Invalid signature")]
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

    /// Returns the tag of the enum as a string, mainly for metrics purposes
    pub const fn to_tag_str(&self) -> &'static str {
        match self {
            Self::BaseFeeTooLow(_) => "base_fee_too_low",
            Self::BlobBaseFeeTooLow(_) => "blob_base_fee_too_low",
            Self::BlobValidation(_) => "blob_validation",
            Self::MaxBaseFeeCalcOverflow => "max_base_fee_calc_overflow",
            Self::NonceTooLow(_, _) => "nonce_too_low",
            Self::NonceTooHigh(_, _) => "nonce_too_high",
            Self::AccountHasCode => "account_has_code",
            Self::GasLimitTooHigh => "gas_limit_too_high",
            Self::TransactionSizeTooHigh => "transaction_size_too_high",
            Self::MaxPriorityFeePerGasTooHigh => "max_priority_fee_per_gas_too_high",
            Self::MaxPriorityFeePerGasTooLow(_, _) => "max_priority_fee_per_gas_too_low",
            Self::InsufficientBalance => "insufficient_balance",
            Self::Pricing(_) => "pricing",
            Self::Eip4844Limit => "eip4844_limit",
            Self::SlotTooLow(_) => "slot_too_low",
            Self::MaxCommittedGasReachedForSlot(_, _) => "max_committed_gas_reached_for_slot",
            Self::Signature(_) => "signature",
            Self::RecoverSigner => "recover_signer",
            Self::ChainIdMismatch => "chain_id_mismatch",
            Self::Internal(_) => "internal",
        }
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
    /// The cached account states. These only contain the
    /// canonical account states at the head block, not the intermediate states.
    ///
    /// INVARIANT: the entries are modified only when receiving a new head.
    account_states: AccountStateCache,
    /// The block templates by target SLOT NUMBER.
    /// We have multiple block templates because in rare cases we might have multiple
    /// proposal duties for a single lookahead.
    ///
    /// INVARIANT: contains only entries for slots greater than or equal to the latest known beacon
    /// chain head.
    /// See [ExecutionState::remove_block_templates_until].
    block_templates: HashMap<Slot, BlockTemplate>,
    /// The chain ID of the chain (constant).
    chain_id: u64,
    /// The limits set for the sidecar.
    limits: LimitsOpts,
    /// The KZG settings for validating blobs.
    kzg_settings: EnvKzgSettings,
    /// The state fetcher client.
    client: C,
    /// Other values used for validation
    validation_params: ValidationParams,
    /// Pricing calculator for preconfirmations.
    pricing: InclusionPricer,
}

/// Other values used for validation.
#[derive(Debug)]
pub struct ValidationParams {
    // The maximum amount of gas reserved to preconfirmations for blocks.
    pub preconf_gas_limit: u64,
    pub max_tx_input_bytes: usize,
    pub max_init_code_byte_size: usize,
}

impl ValidationParams {
    pub fn new(gas_limit: u64) -> Self {
        Self {
            preconf_gas_limit: gas_limit,
            max_tx_input_bytes: 4 * 32 * 1024,
            max_init_code_byte_size: 2 * 24576,
        }
    }
}

impl<C: StateFetcher> ExecutionState<C> {
    /// Creates a new state with the given client, initializing the
    /// basefee and head block number.
    pub async fn new(client: C, limits: LimitsOpts) -> Result<Self, TransportError> {
        let (basefee, blob_basefee, block_number, chain_id) = tokio::try_join!(
            client.get_basefee(None),
            client.get_blob_basefee(None),
            client.get_head(),
            client.get_chain_id()
        )?;

        // Calculate the number of account states that can be cached by diving the configured max
        // size by the size of an account state and its key.
        let num_accounts = limits
            .max_account_states_size
            .get()
            .div_ceil(size_of::<AccountState>() + size_of::<Address>());

        Ok(Self {
            basefee,
            blob_basefee,
            block_number,
            chain_id,
            limits,
            client,
            slot: 0,
            account_states: AccountStateCache(ScoreCache::with_max_len(num_accounts)),
            block_templates: HashMap::new(),
            // Load the default KZG settings
            kzg_settings: EnvKzgSettings::default(),
            // TODO: add a way to configure these values from CLI
            validation_params: ValidationParams::new(limits.max_committed_gas_per_slot.get()),
            pricing: InclusionPricer::new(limits.max_committed_gas_per_slot.get()),
        })
    }

    /// Returns the current base fee in gwei
    pub fn basefee(&self) -> u128 {
        self.basefee
    }

    /// Get the canonical account state at the head of the block for the given address from the
    /// [AccountStateCache]. If not available, it's fetched from the EL client, added to the cache
    /// and returned.
    pub async fn get_or_fetch_account_state(
        &mut self,
        address: Address,
    ) -> Result<AccountState, TransportError> {
        match self.account_states.get(&address) {
            Some(account) => Ok(*account),
            None => {
                let account = self.client.get_account_state(&address, None).await?;
                self.account_states.insert(address, account);
                Ok(account)
            }
        }
    }

    /// Validates the commitment request against state (historical + intermediate).
    ///
    /// NOTE: This function only simulates against execution state, it does not consider
    /// timing or proposer slot targets.
    ///
    /// If the commitment is invalid because of nonce, basefee or balance errors, it will return an
    /// error. If the commitment is valid, its account state
    /// will be cached. If this is succesful, any callers can be sure that the commitment is valid
    /// and SHOULD sign it and respond to the requester.
    ///
    /// TODO: should also validate everything in https://github.com/paradigmxyz/reth/blob/9aa44e1a90b262c472b14cd4df53264c649befc2/crates/transaction-pool/src/validate/eth.rs#L153
    pub async fn validate_request(
        &mut self,
        req: &mut InclusionRequest,
    ) -> Result<(), ValidationError> {
        req.recover_signers()?;

        let target_slot = req.slot;

        // Validate the chain ID
        if !req.validate_chain_id(self.chain_id) {
            return Err(ValidationError::ChainIdMismatch);
        }

        // Check if the committed gas exceeds the maximum
        let template_committed_gas =
            self.get_block_template(target_slot).map(|t| t.committed_gas()).unwrap_or(0);

        if template_committed_gas + req.gas_limit() >= self.limits.max_committed_gas_per_slot.get()
        {
            return Err(ValidationError::MaxCommittedGasReachedForSlot(
                self.slot,
                self.limits.max_committed_gas_per_slot.get(),
            ));
        }

        // Check if the transaction size exceeds the maximum
        if !req.validate_tx_size_limit(self.validation_params.max_tx_input_bytes) {
            return Err(ValidationError::TransactionSizeTooHigh);
        }

        // Check if the transaction is a contract creation and the init code size exceeds the
        // maximum
        if !req.validate_init_code_limit(self.validation_params.max_init_code_byte_size) {
            return Err(ValidationError::TransactionSizeTooHigh);
        }

        // Check if the gas limit is higher than the preconf gas limit
        if req.gas_limit() > self.validation_params.preconf_gas_limit {
            return Err(ValidationError::GasLimitTooHigh);
        }

        // Ensure max_priority_fee_per_gas is less than max_fee_per_gas
        if !req.validate_max_priority_fee() {
            return Err(ValidationError::MaxPriorityFeePerGasTooHigh);
        }

        // Check if the max_fee_per_gas would cover the maximum possible basefee.
        let slot_diff = target_slot.saturating_sub(self.slot);

        // Calculate the max possible basefee given the slot diff
        let max_basefee = calculate_max_basefee(self.basefee, slot_diff)
            .ok_or(ValidationError::MaxBaseFeeCalcOverflow)?;

        debug!(%slot_diff, basefee = self.basefee, %max_basefee, "Validating basefee");

        // Validate the base fee
        if !req.validate_basefee(max_basefee) {
            return Err(ValidationError::BaseFeeTooLow(max_basefee));
        }

        // Ensure max_priority_fee_per_gas is greater than or equal to the calculated
        // min_priority_fee
        if let Err(err) = req.validate_min_priority_fee(
            &self.pricing,
            template_committed_gas,
            self.limits.min_inclusion_profit,
            max_basefee,
        ) {
            return Err(match err {
                pricing::PricingError::TipTooLow { tip, min_priority_fee } => {
                    ValidationError::MaxPriorityFeePerGasTooLow(tip, min_priority_fee)
                }
                other => ValidationError::Pricing(other),
            });
        }

        if target_slot < self.slot {
            debug!(%target_slot, %self.slot, "Target slot lower than current slot");
            return Err(ValidationError::SlotTooLow(self.slot));
        }

        // Validate each transaction in the request against the account state,
        // keeping track of the nonce and balance diffs, including:
        // - any existing state in the account trie
        // - any previously committed transactions
        // - any previous transaction in the same request
        //
        // NOTE: it's also possible for a request to contain multiple transactions
        // from different senders, in this case each sender will have its own nonce
        // and balance diffs that will be applied to the account state.
        let mut bundle_nonce_diff_map = HashMap::new();
        let mut bundle_balance_diff_map = HashMap::new();
        for tx in &req.txs {
            let sender = tx.sender().expect("Recovered sender");

            let (account_diff, highest_slot_for_account) =
                compute_diffs(&self.block_templates, sender);

            if target_slot < highest_slot_for_account {
                debug!(%target_slot, %highest_slot_for_account, "There is a request for a higher slot");
                return Err(ValidationError::SlotTooLow(highest_slot_for_account));
            }

            let account_state = self.get_or_fetch_account_state(*sender).await.map_err(|e| {
                ValidationError::Internal(format!("Error fetching account state: {:?}", e))
            })?;

            debug!(?account_state, ?account_diff, "Validating transaction");

            let sender_nonce_diff = bundle_nonce_diff_map.entry(sender).or_insert(0);
            let sender_balance_diff = bundle_balance_diff_map.entry(sender).or_insert(U256::ZERO);

            // Apply the diffs to this account according to the info fetched from the templates
            // and the current bundle diffs for this sender.
            let account_state_with_diffs = AccountState {
                transaction_count: account_state
                    .transaction_count
                    .saturating_add(account_diff.nonce())
                    .saturating_add(*sender_nonce_diff),

                balance: account_diff
                    .balance()
                    .apply(account_state.balance)
                    .saturating_sub(*sender_balance_diff),
                has_code: account_state.has_code,
            };

            // Validate the transaction against the account state with existing diffs
            validate_transaction(&account_state_with_diffs, tx)?;

            // Check EIP-4844-specific limits
            if let Some(transaction) = tx.as_eip4844_with_sidecar() {
                if let Some(template) = self.block_templates.get(&target_slot) {
                    if template.blob_count() >= MAX_BLOBS_PER_BLOCK {
                        return Err(ValidationError::Eip4844Limit);
                    }
                }

                // Calculate max possible increase in blob basefee
                let max_blob_basefee = calculate_max_basefee(self.blob_basefee, slot_diff)
                    .ok_or(ValidationError::MaxBaseFeeCalcOverflow)?;

                let blob_basefee = transaction.max_fee_per_blob_gas().unwrap_or(0);

                debug!(%max_blob_basefee, %blob_basefee, "Validating blob basefee");
                if blob_basefee < max_blob_basefee {
                    return Err(ValidationError::BlobBaseFeeTooLow(max_blob_basefee));
                }

                // Validate blob against KZG settings
                transaction.validate_blob(self.kzg_settings.get())?;
            }

            // Increase the bundle nonce and balance diffs for this sender for the next iteration
            *sender_nonce_diff += 1;
            *sender_balance_diff += max_transaction_cost(tx);
        }

        Ok(())
    }

    /// Commits the transaction to the target block. Initializes a new block template
    /// if one does not exist for said block number.
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
        trace!(%slot, ?update, "Applying execution state update");

        // Remove any block templates that are no longer valid
        // NOTE: this needs to be called BEFORE applying the state update or we might remove
        // constraints for which we need to get the receipts.
        for template in self.remove_block_templates_until(slot) {
            debug!(%slot, "Removed block template for slot");
            let hashes = template.transaction_hashes();
            let receipts = self.client.get_receipts_unordered(hashes.as_ref()).await?;

            let mut receipts_len = 0;
            for receipt in receipts.iter().flatten() {
                // Calculate the total tip revenue for this transaction:
                // (effective_gas_price - basefee) * gas_used
                let tip_per_gas = receipt.effective_gas_price - self.basefee;
                let total_tip = tip_per_gas * receipt.gas_used as u128;

                trace!(hash = %receipt.transaction_hash, total_tip, "Receipt found");

                ApiMetrics::increment_gross_tip_revenue(total_tip);
                receipts_len += 1;
            }

            // Sanity check with additional logs if there are any discrepancies
            if hashes.len() != receipts_len {
                warn!(
                    %slot,
                    template_hashes = hashes.len(),
                    receipts_found = receipts_len,
                    "mismatch between template transaction hashes and receipts found from client"
                );
                hashes.iter().for_each(|hash| {
                    if !receipts.iter().flatten().any(|receipt| receipt.transaction_hash == *hash) {
                        warn!(%hash, "missing receipt for transaction");
                    }
                });
            }
        }

        self.apply_state_update(update);

        Ok(())
    }

    fn apply_state_update(&mut self, update: StateUpdate) {
        // Update head and basefee
        self.block_number = update.block_number;
        self.basefee = update.min_basefee;

        for (address, state) in update.account_states {
            let Some(prev_state) = self.account_states.get_mut(&address) else {
                error!(%address, "Account state requested for update but not found in cache");
                continue;
            };
            *prev_state = state
        }

        self.refresh_templates();
    }

    /// Refreshes the block templates with the latest account states and removes any invalid
    /// transactions by checking the nonce and balance of the account after applying the state
    /// diffs.
    fn refresh_templates(&mut self) {
        for (address, (account_state, _)) in self.account_states.iter() {
            trace!(%address, ?account_state, "Refreshing templates...");

            // `expected_account_state` is the account state after applying the state diff,
            // that is the account state we expect after applying all transactions in a block
            // template
            let (address, mut expected_account_state) = (*address, *account_state);

            // Iterate over all block templates and apply the state diff
            for template in self.block_templates.values_mut() {
                // Retain only signed constraints where transactions are still valid based on the
                // canonical account states.
                template.retain(address, expected_account_state);

                // Update the account state with the remaining state diff for the next iteration.
                if let Some(account_diff) = template.get_diff(&address) {
                    // Nonce will always be increased
                    expected_account_state.transaction_count += account_diff.nonce();
                    // Re-apply balance diffs
                    expected_account_state.balance =
                        expected_account_state.balance.apply_diff(account_diff.balance())
                }
            }
        }
    }

    /// Gets the block template for the given slot number.
    pub fn get_block_template(&mut self, slot: u64) -> Option<&BlockTemplate> {
        self.block_templates.get(&slot)
    }

    /// Removes all the block templates which slot is less then or equal `slot`, and returns them.
    ///
    /// This should be called when we need to propose a block for the given slot, or when a new
    /// head comes in which makes an older block templates useless.
    ///
    /// NOTE: We remove all previous block templates to ensure that, when a new head is received
    /// from the beacon client, all stale template are cleared. This prevents outdated templates
    /// from persisting in cases of missed slots, where such events are not emitted.
    pub fn remove_block_templates_until(&mut self, slot: u64) -> Vec<BlockTemplate> {
        let mut slots_to_remove =
            self.block_templates.keys().filter(|s| **s <= slot).copied().collect::<Vec<_>>();
        slots_to_remove.sort();

        let mut templates = Vec::with_capacity(slots_to_remove.len());
        for s in slots_to_remove {
            if let Some(template) = self.block_templates.remove(&s) {
                templates.push(template);
            }
        }

        templates
    }
}

#[derive(Debug, Clone)]
pub struct StateUpdate {
    pub account_states: HashMap<Address, AccountState>,
    pub min_basefee: u128,
    pub min_blob_basefee: u128,
    pub block_number: u64,
}

/// Calculate aggregated diffs for an account, given some block templates.
///
/// From previous preconfirmations requests retrieve
/// - the nonce difference from the account state.
/// - the balance difference from the account state.
/// - the highest slot number for which the user has requested a preconfirmation.
///
/// If the templates do not exist, or this is the first request for this sender,
/// its diffs will be zero.
fn compute_diffs(
    block_templates: &HashMap<u64, BlockTemplate>,
    sender: &Address,
) -> (AccountDiff, u64) {
    block_templates.iter().fold(
        (AccountDiff::default(), 0),
        |(diff_acc, highest_slot), (slot, block_template)| {
            let (diff, current_slot) = block_template
                .get_diff(sender)
                .map(|diff| (diff, *slot))
                .unwrap_or((AccountDiff::default(), 0));
            // This might be noisy but it is a critical part in validation logic and
            // hard to debug.
            trace!(account_diff = ?diff, ?slot, ?sender, "found diffs");

            (
                AccountDiff::new(
                    diff_acc.nonce() + diff.nonce(),
                    BalanceDiff::new(
                        diff_acc.balance().increase().saturating_add(diff.balance().increase()),
                        diff_acc.balance().decrease().saturating_add(diff.balance().decrease()),
                    ),
                ),
                u64::max(highest_slot, current_slot),
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::limits::DEFAULT_MAX_COMMITTED_GAS, primitives::diffs::StateDiff,
        signer::local::LocalSigner,
    };
    use std::{num::NonZero, str::FromStr, time::Duration};

    use alloy::{
        consensus::constants::{ETH_TO_WEI, GWEI_TO_WEI},
        eips::eip2718::Encodable2718,
        network::EthereumWallet,
        primitives::{uint, Uint},
        providers::{network::TransactionBuilder, Provider, ProviderBuilder},
        signers::local::PrivateKeySigner,
    };
    use alloy_node_bindings::WEI_IN_ETHER;
    use fetcher::{StateClient, StateFetcher};
    use tracing::info;

    use crate::{
        crypto::SignableBLS,
        primitives::{ConstraintsMessage, SignedConstraints},
        state::fetcher,
        test_util::{create_signed_inclusion_request, default_test_transaction, launch_anvil},
    };

    fn add_constraint(
        request: InclusionRequest,
        state: &mut ExecutionState<StateClient>,
        signer: &LocalSigner,
        target_slot: u64,
    ) -> eyre::Result<()> {
        let message = ConstraintsMessage::build(Default::default(), request.clone());
        let signature = signer.sign_commit_boost_root(message.digest())?;
        let signed_constraints = SignedConstraints { message, signature };
        state.add_constraint(target_slot, signed_constraints);

        Ok(())
    }

    #[test]
    fn test_compute_diff_no_templates() {
        let block_templates = HashMap::new();
        let sender = Address::random();

        let (account_diff, highest_slot) = compute_diffs(&block_templates, &sender);

        assert_eq!(account_diff.nonce(), 0);
        assert_eq!(account_diff.balance().decrease(), U256::ZERO);
        assert_eq!(highest_slot, 0);
    }

    #[test]
    fn test_compute_diff_single_template() {
        // Create a single StateDiff entry
        let sender = Address::random();
        let nonce = 1;
        let balance_diff = U256::from(2);
        let mut diffs = HashMap::new();
        let account_diff = AccountDiff::new(nonce, BalanceDiff::new(U256::ZERO, balance_diff));
        diffs.insert(sender, account_diff);

        // Insert StateDiff entry
        let state_diff = StateDiff { diffs };

        // Create BlockTemplate with StateDiff
        let mut block_templates = HashMap::new();
        let block_template = BlockTemplate { state_diff, signed_constraints_list: vec![] };
        block_templates.insert(10, block_template);

        let (computed_account_diff, highest_slot) = compute_diffs(&block_templates, &sender);

        assert_eq!(computed_account_diff.nonce(), 1);
        assert_eq!(computed_account_diff.balance().decrease(), U256::from(2));
        assert_eq!(highest_slot, 10);
    }

    #[tokio::test]
    async fn test_valid_inclusion_request() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx = default_test_transaction(*sender, None);

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(state.validate_request(&mut request).await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_slot() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Create a transaction with a nonce that is too high
        let tx = default_test_transaction(*sender, Some(1));

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        // Insert a constraint diff for slot 11
        let mut diffs = HashMap::new();
        diffs.insert(*sender, AccountDiff::new(1, BalanceDiff::default()));
        state.block_templates.insert(
            11,
            BlockTemplate { state_diff: StateDiff { diffs }, signed_constraints_list: vec![] },
        );
        state.update_head(None, 11).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::SlotTooLow(11))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_nonce() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Insert a constraint diff for slot 9 to simulate nonce increment
        let mut diffs = HashMap::new();
        diffs.insert(*sender, AccountDiff::new(1, BalanceDiff::default()));
        state.block_templates.insert(
            9,
            BlockTemplate { state_diff: StateDiff { diffs }, signed_constraints_list: vec![] },
        );

        // Create a transaction with a nonce that is too low
        let tx = default_test_transaction(*sender, Some(0));

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::NonceTooLow(1, 0))
        ));

        assert!(state.account_states.get(sender).unwrap().transaction_count == 0);

        // Create a transaction with a nonce that is too high
        let tx = default_test_transaction(*sender, Some(2));

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::NonceTooHigh(1, 2))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_balance() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Create a transaction with a value that is too high
        let tx = default_test_transaction(*sender, None)
            .with_value(uint!(11_000_U256 * Uint::from(ETH_TO_WEI)));

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::InsufficientBalance)
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_balance_multiple() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = LocalSigner::random();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Set the sender balance to just enough to pay for 1 transaction
        let balance = U256::from_str("1200000000000000").unwrap(); // leave just 0.0005 ETH
        let sender_account = client.get_account_state(sender, None).await.unwrap();
        let balance_to_burn = sender_account.balance - balance;

        // burn the balance
        let tx = default_test_transaction(*sender, Some(0)).with_value(uint!(balance_to_burn));
        let request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;
        let tx_bytes = request.txs.first().unwrap().encoded_2718();
        let _ = client.inner().send_raw_transaction(tx_bytes.into()).await?;

        // wait for the transaction to be included to update the sender balance
        tokio::time::sleep(Duration::from_secs(2)).await;
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // create a new transaction and request a preconfirmation for it
        let tx = default_test_transaction(*sender, Some(1));
        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        let validation = state.validate_request(&mut request).await;
        assert!(validation.is_ok(), "Validation failed: {validation:?}");

        let message = ConstraintsMessage::build(Default::default(), request.clone());
        let signature = signer.sign_commit_boost_root(message.digest())?;
        let signed_constraints = SignedConstraints { message, signature };
        state.add_constraint(10, signed_constraints);

        // create a new transaction and request a preconfirmation for it
        let tx = default_test_transaction(*sender, Some(2));
        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        // this should fail because the balance is insufficient as we spent
        // all of it on the previous preconfirmation
        let validation_result = state.validate_request(&mut request).await;

        assert!(
            matches!(validation_result, Err(ValidationError::InsufficientBalance)),
            "Expected InsufficientBalance error, got {:?}",
            validation_result
        );

        Ok(())
    }

    /// Tests that a balance increase allows the recipient to send a transaction using preconfirmed
    /// state.
    #[tokio::test]
    async fn test_balance_increase() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = LocalSigner::random();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;
        let target_slot = 10;

        let recipient_sk = PrivateKeySigner::random();
        let recipient_pk = recipient_sk.address();

        // Create a transfer of 1 ETH to the recipient
        let tx = default_test_transaction(*sender, Some(0))
            .with_to(recipient_pk)
            .with_value(WEI_IN_ETHER);
        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        let validation = state.validate_request(&mut request).await;
        assert!(validation.is_ok(), "Validation failed: {validation:?}");

        add_constraint(request.clone(), &mut state, &signer, target_slot)?;

        // Now the sender should have enough balance to send a transaction
        let tx = default_test_transaction(recipient_pk, Some(0))
            .with_value(WEI_IN_ETHER.div_ceil(U256::from(2)));
        let mut request =
            create_signed_inclusion_request(&[tx], recipient_sk.to_bytes().as_slice(), 10).await?;

        let validation_result = state.validate_request(&mut request).await;

        add_constraint(request, &mut state, &signer, target_slot)?;

        assert!(validation_result.is_ok(), "validation failed: {validation_result:?}");

        // The recipient cannot afford a second transfer of 0.5 ETH
        let tx = default_test_transaction(recipient_pk, Some(1))
            .with_value(WEI_IN_ETHER.div_ceil(U256::from(2)));
        let mut request =
            create_signed_inclusion_request(&[tx], recipient_sk.to_bytes().as_slice(), 10).await?;

        let validation_result = state.validate_request(&mut request).await;
        assert!(
            matches!(validation_result, Err(ValidationError::InsufficientBalance)),
            "Expected InsufficientBalance error, got {:?}",
            validation_result
        );

        Ok(())
    }

    /// Tests that a balance increase is dropped if the preconfirmation is cancelled.
    #[tokio::test]
    async fn test_balance_increase_dropped() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = LocalSigner::random();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;
        let target_slot = slot;

        let recipient_sk = PrivateKeySigner::random();
        let recipient_pk = recipient_sk.address();

        // Create a transfer of 1 ETH to the recipient
        let tx = default_test_transaction(*sender, Some(0))
            .with_to(recipient_pk)
            .with_value(WEI_IN_ETHER);
        let mut request =
            create_signed_inclusion_request(&[tx.clone()], &sender_pk.to_bytes(), 10).await?;

        let validation = state.validate_request(&mut request).await;
        assert!(validation.is_ok(), "Validation failed: {validation:?}");

        add_constraint(request.clone(), &mut state, &signer, target_slot)?;

        // Send a cancel tx
        let tx = default_test_transaction(*sender, Some(0))
            .with_to(*sender)
            .with_max_priority_fee_per_gas(tx.max_priority_fee_per_gas.unwrap() + 1);

        let _ = client.inner().send_transaction(tx).await?;

        // Wait 1s, update the head to include the cancel tx; the constraint should be dropped
        tokio::time::sleep(Duration::from_secs(1)).await;
        state.update_head(None, slot + 1).await?;

        // Now the recipient should not have balance
        let tx = default_test_transaction(recipient_pk, Some(0)).with_value(U256::from(1));
        let mut request = create_signed_inclusion_request(
            &[tx],
            recipient_sk.to_bytes().as_slice(),
            target_slot + 1,
        )
        .await?;

        let validation_result = state.validate_request(&mut request).await;

        assert!(
            matches!(validation_result, Err(ValidationError::InsufficientBalance)),
            "Expected InsufficientBalance error, got {:?}",
            validation_result
        );

        Ok(())
    }

    /// Tests that a chained preconfirmation is dropped if the previous one is cancelled.
    #[tokio::test]
    async fn test_chained_preconfs_dropped() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = LocalSigner::random();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;
        let target_slot = slot + 2;

        let recipient_sk = PrivateKeySigner::random();
        let recipient_pk = recipient_sk.address();

        // Create a transfer of 1 ETH to the recipient
        let tx_1 = default_test_transaction(*sender, Some(0))
            .with_to(recipient_pk)
            .with_value(WEI_IN_ETHER);
        let mut request =
            create_signed_inclusion_request(&[tx_1.clone()], &sender_pk.to_bytes(), 10).await?;

        let validation = state.validate_request(&mut request).await;
        assert!(validation.is_ok(), "Validation failed: {validation:?}");

        add_constraint(request.clone(), &mut state, &signer, target_slot)?;

        // Now the sender should have enough balance to send a transaction
        let tx_2 = default_test_transaction(recipient_pk, Some(0))
            .with_value(WEI_IN_ETHER.div_ceil(U256::from(2)));
        let mut request =
            create_signed_inclusion_request(&[tx_2], recipient_sk.to_bytes().as_slice(), 10)
                .await?;

        let validation_result = state.validate_request(&mut request).await;

        add_constraint(request, &mut state, &signer, target_slot)?;

        assert!(validation_result.is_ok(), "validation failed: {validation_result:?}");

        // Cancel the first preconfirmation request so that both preconfs are dropped.

        // Send a cancel tx
        let tx_3 = default_test_transaction(*sender, Some(0))
            .with_to(*sender)
            .with_max_priority_fee_per_gas(tx_1.max_priority_fee_per_gas.unwrap() + 1);

        let _ = client.inner().send_transaction(tx_3).await?;

        // Wait 1s, update the head to include the cancel tx; the constraint should be dropped
        tokio::time::sleep(Duration::from_secs(1)).await;
        state.update_head(None, slot + 1).await?;

        // Check that both preconfs have been dropped

        let template = state.block_templates.get(&target_slot).unwrap();
        assert!(
            template.signed_constraints_list.is_empty(),
            "block template should be empty, but got: {template:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_basefee() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let limits = LimitsOpts::default();
        let mut state = ExecutionState::new(client.clone(), limits).await?;

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

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::BaseFeeTooLow(_))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_with_excess_gas() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let limits = LimitsOpts {
            max_committed_gas_per_slot: NonZero::new(5_000_000).unwrap(),
            ..Default::default()
        };
        let mut state = ExecutionState::new(client.clone(), limits).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx = default_test_transaction(*sender, None).with_gas_limit(6_000_000);

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::MaxCommittedGasReachedForSlot(_, 5_000_000))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_min_priority_fee() -> eyre::Result<()> {
        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let limits = LimitsOpts::default();

        let mut state = ExecutionState::new(client.clone(), limits).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        // Create a transaction with a max priority fee that is too low
        let tx = default_test_transaction(*sender, None)
            .with_max_priority_fee_per_gas(GWEI_TO_WEI as u128 / 2);

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::MaxPriorityFeePerGasTooLow(_, _))
        ));

        // Create a transaction with a max priority fee that is correct
        let tx = default_test_transaction(*sender, None)
            .with_max_priority_fee_per_gas(4 * GWEI_TO_WEI as u128);

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(state.validate_request(&mut request).await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_min_priority_fee_legacy() -> eyre::Result<()> {
        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let limits = LimitsOpts::default();

        let mut state = ExecutionState::new(client.clone(), limits).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let base_fee = state.basefee();
        let Some(max_base_fee) = calculate_max_basefee(base_fee, 10 - slot) else {
            return Err(eyre::eyre!("Failed to calculate max base fee"));
        };

        // Create a transaction with a gas price that is too low
        let tx = default_test_transaction(*sender, None)
            .with_gas_price(max_base_fee + GWEI_TO_WEI as u128 / 2);

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::MaxPriorityFeePerGasTooLow(_, _))
        ));

        // Create a transaction with a gas price that is correct
        let tx = default_test_transaction(*sender, None)
            .with_gas_price(max_base_fee + 4 * GWEI_TO_WEI as u128);

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(state.validate_request(&mut request).await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_inclusion_request_duplicate_batch() -> eyre::Result<()> {
        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let limits = LimitsOpts::default();

        let mut state = ExecutionState::new(client.clone(), limits).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let base_fee = state.basefee();
        let Some(max_base_fee) = calculate_max_basefee(base_fee, 10 - slot) else {
            return Err(eyre::eyre!("Failed to calculate max base fee"));
        };

        // Create a transaction with a gas price that is too low
        let tx = default_test_transaction(*sender, None)
            .with_gas_price(max_base_fee + 4 * GWEI_TO_WEI as u128);

        let mut request =
            create_signed_inclusion_request(&[tx.clone(), tx], &sender_pk.to_bytes(), 10).await?;

        let response = state.validate_request(&mut request).await;
        println!("{response:?}");

        assert!(matches!(response, Err(ValidationError::NonceTooLow(_, _))));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalidate_inclusion_request() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());
        let provider = ProviderBuilder::new().on_http(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

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
        let mut request =
            create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), target_slot).await?;
        let inclusion_request = request.clone();

        assert!(state.validate_request(&mut request).await.is_ok());

        let bls_signer = LocalSigner::random();
        let message = ConstraintsMessage::build(Default::default(), inclusion_request);
        let signature = bls_signer.sign_commit_boost_root(message.digest()).unwrap();
        let signed_constraints = SignedConstraints { message, signature };

        state.add_constraint(target_slot, signed_constraints);

        assert!(state.get_block_template(target_slot).unwrap().transactions_len() == 1);

        let notif = provider.send_raw_transaction(&signed.encoded_2718()).await?;

        // Wait for confirmation
        let receipt = notif.get_receipt().await?;

        // Update the head, which should invalidate the transaction due to a nonce conflict
        state.update_head(receipt.block_number, receipt.block_number.unwrap()).await?;

        let transactions_len = state.get_block_template(target_slot).unwrap().transactions_len();

        assert!(transactions_len == 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_invalidate_stale_template() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx = default_test_transaction(*sender, None);

        let target_slot = 10;
        let mut request =
            create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), target_slot).await?;
        let inclusion_request = request.clone();

        assert!(state.validate_request(&mut request).await.is_ok());

        let bls_signer = LocalSigner::random();
        let message = ConstraintsMessage::build(Default::default(), inclusion_request);
        let signature = bls_signer.sign_commit_boost_root(message.digest()).unwrap();
        let signed_constraints = SignedConstraints { message, signature };

        state.add_constraint(target_slot, signed_constraints);

        assert!(state.get_block_template(target_slot).unwrap().transactions_len() == 1);

        // fast-forward the head to the target slot, which should invalidate the entire template
        // because it's now stale.
        state.update_head(None, target_slot).await?;

        assert!(state.get_block_template(target_slot).is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_invalidate_inclusion_request_with_excess_gas() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let limits = LimitsOpts::default();
        let mut state = ExecutionState::new(client.clone(), limits).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx = default_test_transaction(*sender, None)
            .with_gas_limit(limits.max_committed_gas_per_slot.get() - 1);

        let target_slot = 10;
        let mut request =
            create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), target_slot).await?;
        let inclusion_request = request.clone();

        let validation = state.validate_request(&mut request).await;
        assert!(validation.is_ok(), "{validation:?}");

        let bls_signer = LocalSigner::random();
        let message = ConstraintsMessage::build(Default::default(), inclusion_request);
        let signature = bls_signer.sign_commit_boost_root(message.digest()).unwrap();
        let signed_constraints = SignedConstraints { message, signature };

        state.add_constraint(target_slot, signed_constraints);

        assert!(state.get_block_template(target_slot).unwrap().transactions_len() == 1);

        // This tx will exceed the committed gas limit
        let tx = default_test_transaction(*sender, Some(1));

        let mut request = create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), 10).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::MaxCommittedGasReachedForSlot(_, DEFAULT_MAX_COMMITTED_GAS))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_valid_bundle_inclusion_request() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx1 = default_test_transaction(*sender, Some(0));
        let tx2 = default_test_transaction(*sender, Some(1));
        let tx3 = default_test_transaction(*sender, Some(2));

        let mut request =
            create_signed_inclusion_request(&[tx1, tx2, tx3], &sender_pk.to_bytes(), 10).await?;

        assert!(state.validate_request(&mut request).await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_bundle_inclusion_request_nonce() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx1 = default_test_transaction(*sender, Some(0));
        let tx2 = default_test_transaction(*sender, Some(1));
        let tx3 = default_test_transaction(*sender, Some(3)); // wrong nonce, should be 2

        let mut request =
            create_signed_inclusion_request(&[tx1, tx2, tx3], &sender_pk.to_bytes(), 10).await?;

        assert!(matches!(
            state.validate_request(&mut request).await,
            Err(ValidationError::NonceTooHigh(2, 3))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_bundle_inclusion_request_balance() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        state.update_head(None, slot).await?;

        let tx1 = default_test_transaction(*sender, Some(0));
        let tx2 = default_test_transaction(*sender, Some(1));
        let tx3 = default_test_transaction(*sender, Some(2))
            .with_value(uint!(11_000_U256 * Uint::from(ETH_TO_WEI)));

        let mut request =
            create_signed_inclusion_request(&[tx1, tx2, tx3], &sender_pk.to_bytes(), 10).await?;
        let validation_result = state.validate_request(&mut request).await;

        assert!(
            matches!(validation_result, Err(ValidationError::InsufficientBalance)),
            "Expected InsufficientBalance error, got {:?}",
            validation_result
        );

        Ok(())
    }

    /// Sends two inclusion request for the same target slot during two different slots, and makes
    /// sure the nonces are checked correctly.
    #[tokio::test]
    async fn test_subsequent_inclusion_request() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let anvil = launch_anvil();
        let client = StateClient::new(anvil.endpoint_url());

        let mut state = ExecutionState::new(client.clone(), LimitsOpts::default()).await?;

        let sender = anvil.addresses().first().unwrap();
        let sender_pk = anvil.keys().first().unwrap();

        // initialize the state by updating the head once
        let slot = client.get_head().await?;
        info!(?slot);
        state.update_head(None, slot).await?;

        // 1. Send an inclusion request at `slot` with `target_slot`.
        let target_slot = 32;
        let tx = default_test_transaction(*sender, None).with_gas_price(ETH_TO_WEI / 1_000_000);

        let mut request =
            create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), target_slot).await?;
        let inclusion_request = request.clone();

        let request_validation = state.validate_request(&mut request).await;
        println!("request validation = {:?}", request_validation);
        assert!(request_validation.is_ok());

        let bls_signer = LocalSigner::random();
        let message = ConstraintsMessage::build(Default::default(), inclusion_request);
        let signature = bls_signer.sign_commit_boost_root(message.digest()).unwrap();
        let signed_constraints = SignedConstraints { message, signature };

        state.add_constraint(target_slot, signed_constraints);

        assert_eq!(state.get_block_template(target_slot).unwrap().transactions_len(), 1);

        // Update the head to next slot
        state.update_head(None, slot + 1).await?;

        // 2. Send an inclusion request at `slot + 1` with `target_slot`.
        let tx = default_test_transaction(*sender, Some(1)).with_gas_price(ETH_TO_WEI / 1_000_000);
        let mut request =
            create_signed_inclusion_request(&[tx], &sender_pk.to_bytes(), target_slot).await?;
        let inclusion_request = request.clone();

        let request_validation = state.validate_request(&mut request).await;
        println!("request validation = {:?}", request_validation);
        assert!(request_validation.is_ok());

        let bls_signer = LocalSigner::random();
        let message = ConstraintsMessage::build(Default::default(), inclusion_request);
        let signature = bls_signer.sign_commit_boost_root(message.digest()).unwrap();
        let signed_constraints = SignedConstraints { message, signature };

        state.add_constraint(target_slot, signed_constraints);

        assert_eq!(state.get_block_template(target_slot).unwrap().transactions_len(), 2);

        Ok(())
    }
}
