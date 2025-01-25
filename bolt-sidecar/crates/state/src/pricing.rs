/// Gas limit constants
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Fee calculation constants from
/// https://research.lido.fi/t/a-pricing-model-for-inclusion-preconfirmations/9136#p-19482-a-model-for-cumulative-proposer-rewards-13
const BASE_MULTIPLIER: f64 = 0.019;
const GAS_SCALAR: f64 = 1.02e-6;

/// Handles pricing calculations for preconfirmations
#[derive(Debug)]
pub struct InclusionPricer {
    block_gas_limit: u64,
    base_multiplier: f64,
    gas_scalar: f64,
}

/// Errors that can occur during pricing calculations
#[derive(Debug, thiserror::Error)]
pub enum PricingError {
    /// Preconfirmed gas exceeds the block limit
    #[error("Preconfirmed gas {0} exceeds block limit {1}")]
    ExceedsBlockLimit(u64, u64),
    /// Insufficient remaining gas for the incoming transaction
    #[error("Insufficient remaining gas: requested {requested}, available {available}")]
    /// Insufficient remaining gas for the incoming transaction
    InsufficientGas {
        /// Gas requested by the incoming transaction
        requested: u64,
        /// Gas available in the block
        available: u64,
    },
    /// Incoming gas is zero
    #[error("Invalid gas limit: Incoming gas ({incoming_gas}) is zero")]
    InvalidGasLimit {
        /// Gas required by the incoming transaction
        incoming_gas: u64,
    },

    /// Tip is too low for the required minimum priority fee
    #[error("Tip {tip} is too low. Minimum required priority fee is {min_priority_fee}")]
    TipTooLow {
        /// Tip provided by the transaction
        tip: u128,
        /// The minimum priority fee required
        min_priority_fee: u128,
    },
}

impl Default for InclusionPricer {
    fn default() -> Self {
        Self::new(DEFAULT_BLOCK_GAS_LIMIT)
    }
}

impl InclusionPricer {
    /// Initializes a new InclusionPricer with default parameters.
    pub fn new(block_gas_limit: u64) -> Self {
        Self { block_gas_limit, base_multiplier: BASE_MULTIPLIER, gas_scalar: GAS_SCALAR }
    }

    /// Calculate the minimum inclusion fee for a preconfirmation based on
    /// https://research.lido.fi/t/a-pricing-model-for-inclusion-preconfirmations/9136
    ///
    /// # Arguments
    /// * `incoming_gas` - Gas required by the incoming transaction
    /// * `preconfirmed_gas` - Total gas already preconfirmed
    ///
    /// # Returns
    /// * `Ok(u64)` - The minimum inclusion fee in Wei per gas
    /// * `Err(PricingError)` - If the calculation cannot be performed
    ///
    /// Be careful relying on the result of this when preconfirmed gas is close to 30M
    /// """
    /// This being said our model becomes less reliable as the amount of gas
    /// preconfirmed approaches 30M. There are many reasons for this, but one
    /// important reason is that we omit large outlier transactions to improve average
    /// fit, which disproportionately affects the most valuable transactions.
    /// """
    pub fn calculate_min_priority_fee(
        &self,
        incoming_gas: u64,
        preconfirmed_gas: u64,
    ) -> Result<u64, PricingError> {
        validate_fee_inputs(incoming_gas, preconfirmed_gas, self.block_gas_limit)?;
        // T(IG,UG) = 0.019 * ln(1.02⋅10^-6(30M-UG)+1 / 1.02⋅10^-6(30M-UG-IG)+1) / IG
        // where
        // IG = Gas used by the incoming transaction
        // UG = Gas already preconfirmed
        // T = Inclusion tip per gas
        // 30M = Current gas limit (36M soon?)
        let remaining_gas = self.block_gas_limit - preconfirmed_gas;
        let after_gas = remaining_gas - incoming_gas;

        // Calculate numerator and denominator for the logarithm
        let fraction = (self.gas_scalar * (remaining_gas as f64) + 1.0) /
            (self.gas_scalar * (after_gas as f64) + 1.0);

        // Calculate block space value in Ether
        let block_space_value = self.base_multiplier * fraction.ln();

        // Convert to Wei
        let inclusion_tip_wei = (block_space_value * 1e18) as u64;

        // Calculate the fee per gas
        Ok(inclusion_tip_wei / incoming_gas)
    }
}

fn validate_fee_inputs(
    incoming_gas: u64,
    preconfirmed_gas: u64,
    gas_limit: u64,
) -> Result<(), PricingError> {
    // Check if preconfirmed gas exceeds block limit
    if preconfirmed_gas >= gas_limit {
        return Err(PricingError::ExceedsBlockLimit(preconfirmed_gas, gas_limit));
    }

    // Validate incoming gas
    if incoming_gas == 0 {
        return Err(PricingError::InvalidGasLimit { incoming_gas });
    }

    // Check if there is enough gas remaining in the block
    let remaining_gas = gas_limit - preconfirmed_gas;
    if incoming_gas > remaining_gas {
        return Err(PricingError::InsufficientGas {
            requested: incoming_gas,
            available: remaining_gas,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_priority_fee_zero_preconfirmed() {
        let pricing = InclusionPricer::default();

        // Test minimum fee (21k gas ETH transfer, 0 preconfirmed)
        let incoming_gas = 21_000;
        let preconfirmed_gas = 0;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        // Pricing model article expects fee of 0.61 Gwei
        assert!(
            (min_fee_wei as f64 - 613_499_092.0).abs() < 1_000.0,
            "Expected ~613,499,092 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_medium_load() {
        let pricing = InclusionPricer::default();

        // Test medium load (21k gas, 15M preconfirmed)
        let incoming_gas = 21_000;
        let preconfirmed_gas = 15_000_000;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        // Pricing model article expects fee of ~1.17 Gwei
        assert!(
            (min_fee_wei as f64 - 1_189_738_950.0).abs() < 1_000.0,
            "Expected ~1,189,738,950 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_max_load() {
        let pricing = InclusionPricer::default();

        // Test last preconfirmed transaction (21k gas, almost 30M preconfirmed)
        let incoming_gas = 21_000;
        let preconfirmed_gas = 30_000_000 - 21_000;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        // Expected fee: ~19 Gwei
        // This will likely never happen, since you want to reserve some gas
        // on top of the block for MEV, but enforcing this is not the responsibility
        // of the pricing model.
        assert!(
            (min_fee_wei as f64 - 19_175_357_339.0).abs() < 1_000.0,
            "Expected ~19,175,357,339 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_80p() {
        let pricing = InclusionPricer::default();

        // Test preconfirmed transaction when 80% of the block is already used
        let incoming_gas = 21_000;
        let preconfirmed_gas = (30_000_000_f64 * 0.8) as u64;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        // Expected fee: ~
        assert!(
            (min_fee_wei as f64 - 2_726_012_676.0).abs() < 1_000.0,
            "Expected ~2,726,012,676 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_zero_big_preconfirmed() {
        let pricing = InclusionPricer::default();

        // Test minimum fee (210k gas ETH transfer, 0 preconfirmed)
        let big_gas = 210_000;
        let preconfirmed_gas_big = 0;
        let big_fee = pricing.calculate_min_priority_fee(big_gas, preconfirmed_gas_big).unwrap();

        // Test minimum fee (10x21k gas ETH transfer, 0 preconfirmed)
        let small_gas = 21_000;
        let mut preconfirmed_gas_small = 0;
        let mut small_fee_sum = 0;
        for _ in 0..10 {
            let small_fee =
                pricing.calculate_min_priority_fee(small_gas, preconfirmed_gas_small).unwrap();
            small_fee_sum += small_fee;
            preconfirmed_gas_small += small_gas;
        }

        // Moving on the pricing curve in 10 steps should cost
        // the same as moving in one big step per gas.
        let small_sum_fee_avg = small_fee_sum / 10;

        assert!(
            (big_fee as f64 - small_sum_fee_avg as f64).abs() < 1_000.0,
            "Expected big preconf to cost the same as many small ones, big {} Wei, small {} Wei",
            big_fee,
            small_fee_sum
        );
    }

    #[test]
    fn test_priority_fee_all_gas() {
        let pricing = InclusionPricer::default();

        // Test one preconf for all the available gas
        let incoming_gas = 30_000_000;
        let preconfirmed_gas = 0;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        assert!(
            (min_fee_wei as f64 - 2_186_999_509.0).abs() < 1_000.0,
            "Expected ~2,186,999,509 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_zero_preconfirmed_36m() {
        let pricing = InclusionPricer::new(36_000_000);

        // Test minimum fee (21k gas ETH transfer, 0 preconfirmed)
        let incoming_gas = 21_000;
        let preconfirmed_gas = 0;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        assert!(
            (min_fee_wei as f64 - 513_931_726.0).abs() < 1_000.0,
            "Expected ~513,931,726 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_medium_load_36m() {
        let pricing = InclusionPricer::new(36_000_000);

        // Test medium load (21k gas, 18M preconfirmed)
        let incoming_gas = 21_000;
        let preconfirmed_gas = 18_000_000;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        assert!(
            (min_fee_wei as f64 - 1_001_587_240.0).abs() < 1_000.0,
            "Expected ~1,001,587,240 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_max_load_36m() {
        let pricing = InclusionPricer::new(36_000_000);

        // Test last preconfirmed transaction (21k gas, almost 30M preconfirmed)
        let incoming_gas = 21_000;
        let preconfirmed_gas = 36_000_000 - 21_000;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        // Expected fee: ~19 Gwei
        // This will likely never happen, since you want to reserve some gas
        // on top of the block for MEV, but enforcing this is not the responsibility
        // of the pricing model.
        assert!(
            (min_fee_wei as f64 - 19_175_357_339.0).abs() < 1_000.0,
            "Expected ~19,175,357,339 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_error_exceeds_block_limit() {
        let pricing = InclusionPricer::default();

        let incoming_gas = 21_000;
        let preconfirmed_gas = 30_000_001;

        let result = pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas);
        assert!(matches!(result, Err(PricingError::ExceedsBlockLimit(30_000_001, 30_000_000))));
    }

    #[test]
    fn test_error_insufficient_gas() {
        let pricing = InclusionPricer::default();

        let incoming_gas = 15_000_001;
        let preconfirmed_gas = 15_000_000;

        let result = pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas);
        assert!(matches!(
            result,
            Err(PricingError::InsufficientGas { requested: 15_000_001, available: 15_000_000 })
        ));
    }

    #[test]
    fn test_error_zero_incoming_gas() {
        let pricing = InclusionPricer::default();

        let incoming_gas = 0;
        let preconfirmed_gas = 0;

        let result = pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas);
        assert!(matches!(result, Err(PricingError::InvalidGasLimit { incoming_gas: 0 })));
    }
}
