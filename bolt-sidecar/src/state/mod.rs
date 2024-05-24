//! The `state` module is responsible for keeping a local copy of relevant state that is needed
//! to simulate commitments against. It is updated on every block.
use alloy_primitives::{Address, U256};
use alloy_transport::TransportError;
use futures::{stream::FuturesOrdered, StreamExt};
use std::{collections::HashMap, time::Duration};
use thiserror::Error;

use crate::{
    client::RpcClient,
    common::{calculate_max_basefee, max_transaction_cost},
    template::BlockTemplate,
    types::{commitment::CommitmentRequest, AccountState},
};

/// Maximum retries for RPC requests.
const MAX_RETRIES: u32 = 8;

/// The retry backoff in milliseconds.
const RETRY_BACKOFF_MS: u64 = 200;

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

    /// Tries to commit to the requested commitment. If the commitment is invalid
    /// and fails simulation, it will return an error.
    /// If the commitment is valid, it will be added to the block template and its account state
    /// will be cached.
    pub async fn try_commit(&mut self, request: &CommitmentRequest) -> Result<(), ValidationError> {
        // TODO: more pre-checks
        // - Check if the target slot is actually our proposer slot

        let CommitmentRequest::Inclusion(req) = request;

        // NOTE: for now, we don't accept same-slot inclusion requests.
        // In the future, we can do this (up to a certain deadline like 6s-8s)
        if req.slot <= self.head {
            return Err(ValidationError::SlotTooLow(req.slot));
        }

        // Check if the max_fee_per_gas would cover the maximum possible basefee.
        let slot_diff = req.slot - self.head;

        // TODO: guard against overflows etc?
        // max_base_fee = current_base_fee * 1.125^block_diff
        // let max_basefee = self.basefee as f64 * 1.125f64.powi(slot_diff as i32);

        let max_basefee = calculate_max_basefee(self.basefee, slot_diff).expect("No overflow");

        // Validate the base fee
        if !req.validate_basefee(max_basefee) {
            return Err(ValidationError::FeeTooLow(max_basefee as u128));
        }

        // If we have the account state, use it here
        if let Some(account_state) = self.account_state(&req.transaction.from) {
            // If the transaction nonce is not higher than the current nonce, reject it
            if req.transaction.nonce <= account_state.nonce {
                return Err(ValidationError::NonceTooLow);
            }

            // Check if the balance is enough
            if max_transaction_cost(&req.transaction) > account_state.balance {
                return Err(ValidationError::InsufficientBalance);
            }
        } else {
            // If we don't have the account state, we need to fetch it
            let account_state = self
                .client
                .get_account_state(&req.transaction.from)
                .await
                .map_err(|e| ValidationError::Internal(e.to_string()));
        }

        // - Check if we're violating any of the address state
        // - If not, insert the address state into the state

        // // Get state update for the address at the current head block
        // let update = self
        //     .client
        //     .get_state_update(Some(self.head), vec![address])
        //     .await?;

        // self.apply_state_update(self.head, update);
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

trait StateFetcher {
    async fn get_state_update(
        &self,
        block_number: Option<u64>,
        addresses: Vec<&Address>,
    ) -> Result<StateUpdate, TransportError>;

    async fn get_head(&self) -> Result<u64, TransportError>;
    async fn get_basefee(&self) -> Result<u128, TransportError>;
    async fn get_account_state(&self, address: &Address) -> Result<AccountState, TransportError>;
}

struct StateClient {
    client: RpcClient,
    retry_backoff: Duration,
}

impl StateClient {
    pub fn new(url: &str, max_retries: u32) -> Self {
        let client = RpcClient::new(url);
        Self {
            client,
            retry_backoff: Duration::from_millis(RETRY_BACKOFF_MS),
        }
    }
}

impl StateFetcher for StateClient {
    // TODO: should this be durable i.e. retries?
    // Yes
    async fn get_state_update(
        &self,
        block_number: Option<u64>,
        addresses: Vec<&Address>,
    ) -> Result<StateUpdate, TransportError> {
        // Create a new batch
        let mut batch = self.client.new_batch();

        let mut account_states = HashMap::with_capacity(addresses.len());

        let mut nonce_futs = FuturesOrdered::new();
        let mut balance_futs = FuturesOrdered::new();

        // TODO: add block number in params
        for addr in &addresses {
            // We can use expect here since the only error is related to invalid parameters
            let nonce = batch
                .add_call("eth_getNonce", addr)
                .expect("Invalid parameters");
            let balance = batch
                .add_call("eth_getBalance", addr)
                .expect("Invalid parameters");

            // Push the futures onto ordered list
            nonce_futs.push_back(nonce);
            balance_futs.push_back(balance);
        }

        let basefee = batch.add_call("eth_baseFee", &()).unwrap();
        // Make sure to send the batch!

        // After the batch is complete, we can get the results.
        // Note that requests may error separately!
        batch.send().await?;

        // Collect the results
        let (nonce_vec, balance_vec, basefee) = tokio::join!(
            nonce_futs.collect::<Vec<_>>(),
            balance_futs.collect::<Vec<_>>(),
            basefee
        );

        // Insert the results
        for (addr, nonce) in addresses.iter().zip(nonce_vec) {
            let nonce = nonce?;

            account_states
                .entry(**addr)
                .and_modify(|s: &mut AccountState| {
                    s.nonce = nonce;
                })
                .or_insert(AccountState {
                    nonce,
                    balance: U256::ZERO,
                });
        }

        for (addr, balance) in addresses.iter().zip(balance_vec) {
            let balance = balance?;

            account_states
                .entry(**addr)
                .and_modify(|s: &mut AccountState| {
                    s.balance = balance;
                })
                .or_insert(AccountState { nonce: 0, balance });
        }

        Ok(StateUpdate {
            account_states,
            min_basefee: basefee?,
        })
    }

    async fn get_head(&self) -> Result<u64, TransportError> {
        self.client.get_head().await
    }

    async fn get_basefee(&self) -> Result<u128, TransportError> {
        self.client.get_basefee().await
    }

    async fn get_account_state(&self, address: &Address) -> Result<AccountState, TransportError> {
        let mut retries = 0;

        loop {
            match self.client.get_account_state(address).await {
                Ok(state) => return Ok(state),
                Err(e) => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        return Err(e);
                    }

                    tracing::error!(error = ?e, "Error getting account state, retrying...");
                    tokio::time::sleep(self.retry_backoff).await;
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct StateUpdate {
    account_states: HashMap<Address, AccountState>,
    min_basefee: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_state() {
        let url = std::env::var("RPC_URL").expect("RPC_URL must be set");

        let state = State::new(StateClient::new(&url, 1)).await.unwrap();

        assert_eq!(state.head, 0);
        assert_ne!(state.basefee, 0);
    }
}
