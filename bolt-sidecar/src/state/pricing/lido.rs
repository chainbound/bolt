//! Implementation of preconfirmation pricing as presented in
//! <https://research.lido.fi/t/a-pricing-model-for-inclusion-preconfirmations/9136>.
use super::{Pricing, PricingError, DEFAULT_BLOCK_GAS_LIMIT};

/// Fee calculation constants from
/// <https://research.lido.fi/t/a-pricing-model-for-inclusion-preconfirmations/9136#p-19482-a-model-for-cumulative-proposer-rewards-13>
const BASE_MULTIPLIER: f64 = 0.019;
const GAS_SCALAR: f64 = 1.02e-6;

/// Handles pricing calculations for preconfirmations
#[derive(Debug)]
pub struct LidoPricing {
    block_gas_limit: u64,
    base_multiplier: f64,
    gas_scalar: f64,
}

impl Default for LidoPricing {
    fn default() -> Self {
        Self::new(DEFAULT_BLOCK_GAS_LIMIT)
    }
}

impl LidoPricing {
    /// Initializes a new LidoPricing with default parameters.
    pub fn new(block_gas_limit: u64) -> Self {
        Self { block_gas_limit, base_multiplier: BASE_MULTIPLIER, gas_scalar: GAS_SCALAR }
    }
}

impl Pricing for LidoPricing {
    /// Calculate the minimum priority fee for a preconfirmation based on 
    /// <https://research.lido.fi/t/a-pricing-model-for-inclusion-preconfirmations/9136>
    fn calculate_min_priority_fee(
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
        let numerator = self.gas_scalar * (remaining_gas as f64) + 1.0;
        let denominator = self.gas_scalar * (after_gas as f64) + 1.0;

        // Calculate gas used
        let expected_val = self.base_multiplier * (numerator / denominator).ln();

        // Calculate the inclusion tip
        let inclusion_tip_ether = expected_val / (incoming_gas as f64);
        let inclusion_tip_wei = (inclusion_tip_ether * 1e18) as u64;

        Ok(inclusion_tip_wei)
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
        let pricing = LidoPricing::default();

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
    fn test_min_priority_fee_zero_big_preconfirmed() {
        let pricing = LidoPricing::default();

        // Test minimum fee (210k gas ETH transfer, 0 preconfirmed)
        let incoming_gas = 210_000;
        let preconfirmed_gas = 0;
        let min_fee_wei =
            pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas).unwrap();

        // This preconf uses 10x more gas than the 21k preconf,
        // but the fee is only slightly higher.
        assert!(
            (min_fee_wei as f64 - 615_379_171.0).abs() < 1_000.0,
            "Expected ~615,379,171 Wei, got {} Wei",
            min_fee_wei
        );
    }

    #[test]
    fn test_min_priority_fee_medium_load() {
        let pricing = LidoPricing::default();

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
        let pricing = LidoPricing::default();

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
    fn test_min_priority_fee_zero_preconfirmed_36m() {
        let pricing = LidoPricing::new(36_000_000);

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
        let pricing = LidoPricing::new(36_000_000);

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
        let pricing = LidoPricing::new(36_000_000);

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
        let pricing = LidoPricing::default();

        let incoming_gas = 21_000;
        let preconfirmed_gas = 30_000_001;

        let result = pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas);
        assert!(matches!(result, Err(PricingError::ExceedsBlockLimit(30_000_001, 30_000_000))));
    }

    #[test]
    fn test_error_insufficient_gas() {
        let pricing = LidoPricing::default();

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
        let pricing = LidoPricing::default();

        let incoming_gas = 0;
        let preconfirmed_gas = 0;

        let result = pricing.calculate_min_priority_fee(incoming_gas, preconfirmed_gas);
        assert!(matches!(result, Err(PricingError::InvalidGasLimit { incoming_gas: 0 })));
    }
}
