use alloy_primitives::U256;
use reth_primitives::PooledTransactionsElement;

use crate::{
    primitives::{AccountState, TransactionExt},
    state::ValidationError,
};

/// Calculates the max_basefee `slot_diff` blocks in the future given a current basefee (in gwei).
/// Returns None if an overflow would occur.
/// Cfr. https://github.com/flashbots/ethers-provider-flashbots-bundle/blob/7ddaf2c9d7662bef400151e0bfc89f5b13e72b4c/src/index.ts#L308
pub fn calculate_max_basefee(current: u128, block_diff: u64) -> Option<u128> {
    // Define the multiplier and divisor for fixed-point arithmetic
    let multiplier: u128 = 1125; // Represents 112.5%
    let divisor: u128 = 1000;
    let mut max_basefee = current;

    for _ in 0..block_diff {
        // Check for potential overflow when multiplying
        if max_basefee > u128::MAX / multiplier {
            return None; // Overflow would occur
        }

        // Perform the multiplication and division (and add 1 to round up)
        max_basefee = max_basefee * multiplier / divisor + 1;
    }

    Some(max_basefee)
}

/// Calculates the max transaction cost (gas + value) in wei.
///
/// - For EIP-1559 transactions: `max_fee_per_gas * gas_limit + tx_value`.
/// - For legacy transactions: `gas_price * gas_limit + tx_value`.
/// - For EIP-4844 blob transactions: `max_fee_per_gas * gas_limit + tx_value +
///   max_blob_fee_per_gas * blob_gas_used`.
pub fn max_transaction_cost(transaction: &PooledTransactionsElement) -> U256 {
    let gas_limit = transaction.gas_limit() as u128;

    let mut fee_cap = transaction.max_fee_per_gas();
    fee_cap += transaction.max_priority_fee_per_gas().unwrap_or(0);

    if let Some(eip4844) = transaction.as_eip4844() {
        fee_cap += eip4844.max_fee_per_blob_gas + eip4844.blob_gas() as u128;
    }

    U256::from(gas_limit * fee_cap) + transaction.value()
}

/// This function validates a transaction against an account state. It checks 2 things:
/// 1. The nonce of the transaction must be higher than the account's nonce, but not higher than current + 1.
/// 2. The balance of the account must be higher than the transaction's max cost.
pub fn validate_transaction(
    account_state: &AccountState,
    transaction: &PooledTransactionsElement,
) -> Result<(), ValidationError> {
    // Check if the nonce is correct (should be the same as the transaction count)
    if transaction.nonce() < account_state.transaction_count {
        return Err(ValidationError::NonceTooLow(
            account_state.transaction_count,
            transaction.nonce(),
        ));
    }

    if transaction.nonce() > account_state.transaction_count {
        return Err(ValidationError::NonceTooHigh(
            account_state.transaction_count,
            transaction.nonce(),
        ));
    }

    // Check if the balance is enough
    if max_transaction_cost(transaction) > account_state.balance {
        return Err(ValidationError::InsufficientBalance);
    }

    // Check if the account has code (i.e. is a smart contract)
    if account_state.has_code {
        return Err(ValidationError::AccountHasCode);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_max_basefee() {
        let current = 10_000_000_000; // 10 gwei
        let slot_diff = 9; // 9 full blocks in the future

        let result = calculate_max_basefee(current, slot_diff);
        assert_eq!(result, Some(28865075793))
    }
}
