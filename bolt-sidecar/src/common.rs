use alloy_primitives::U256;
use alloy_rpc_types::Transaction;

/// Calculates the max_basefee `slot_diff` blocks in the future given a current basefee (in gwei).
/// Returns None if an overflow would occur.
/// Cfr. https://github.com/flashbots/ethers-provider-flashbots-bundle/blob/7ddaf2c9d7662bef400151e0bfc89f5b13e72b4c/src/index.ts#L308
pub fn calculate_max_basefee(current: u128, slot_diff: u64) -> Option<u128> {
    // Define the multiplier and divisor for fixed-point arithmetic
    let multiplier: u128 = 1125; // Represents 112.5%
    let divisor: u128 = 1000;
    let mut max_basefee = current;

    for _ in 0..slot_diff {
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
pub fn max_transaction_cost(transaction: &Transaction) -> U256 {
    let gas_limit = transaction.gas;

    let fee_cap = transaction
        .max_fee_per_gas
        .or(transaction.gas_price)
        .expect("Gas price");

    let fee_cap = fee_cap + transaction.max_priority_fee_per_gas.unwrap_or(0);

    U256::from(gas_limit * fee_cap) + transaction.value
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
