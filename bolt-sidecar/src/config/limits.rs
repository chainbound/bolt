use std::num::NonZero;

use clap::Parser;
use serde::Deserialize;

// Default limit values
pub const DEFAULT_MAX_COMMITMENTS: usize = 128;
pub const DEFAULT_MAX_COMMITTED_GAS: u64 = 10_000_000;
pub const DEFAULT_MIN_PRIORITY_FEE: u128 = 1_000_000_000; // 1 Gwei

/// Limits for the sidecar.
#[derive(Debug, Parser, Clone, Copy, Deserialize)]
pub struct LimitsOpts {
    /// Max number of commitments to accept per block
    #[clap(
        long,
        env = "BOLT_SIDECAR_MAX_COMMITMENTS",
        default_value_t = LimitsOpts::default().max_commitments_per_slot
    )]
    pub max_commitments_per_slot: NonZero<usize>,
    /// Max committed gas per slot
    #[clap(
        long,
        env = "BOLT_SIDECAR_MAX_COMMITTED_GAS",
        default_value_t = LimitsOpts::default().max_committed_gas_per_slot
    )]
    pub max_committed_gas_per_slot: NonZero<u64>,
    /// Min priority fee to accept for a commitment
    #[clap(
        long,
        env = "BOLT_SIDECAR_MIN_PRIORITY_FEE",
        default_value_t = LimitsOpts::default().min_priority_fee
    )]
    pub min_priority_fee: u128,
}

impl Default for LimitsOpts {
    fn default() -> Self {
        Self {
            max_commitments_per_slot: NonZero::new(DEFAULT_MAX_COMMITMENTS)
                .expect("Valid non-zero"),
            max_committed_gas_per_slot: NonZero::new(DEFAULT_MAX_COMMITTED_GAS)
                .expect("Valid non-zero"),
            min_priority_fee: DEFAULT_MIN_PRIORITY_FEE,
        }
    }
}
