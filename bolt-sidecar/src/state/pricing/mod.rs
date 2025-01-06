pub mod lido;

pub use lido::LidoPricing;

/// Gas limit constants
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;

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
}

/// Represents a type that is capable of assigning a price to a preconfirmation
pub trait Pricing {
    /// Calculate the minimum priority fee for a preconfirmation
    ///
    /// # Parameters
    /// - `incoming_gas` - Gas required by the incoming transaction
    /// - `preconfirmed_gas` - Total gas already preconfirmed
    ///
    /// # Returns
    /// - `Ok(f64)` - The minimum priority fee in Wei
    /// - `Err(PricingError)` - If the calculation cannot be performed
    ///     (see [`PricingError`])
    fn calculate_min_priority_fee(
        &self,
        incoming_gas: u64,
        preconfirmed_gas: u64,
    ) -> Result<u64, PricingError>;
}
