use alloy_primitives::U256;

pub mod commitment;
pub mod transaction;

/// An alias for a Beacon Chain slot number
pub type Slot = u64;

/// Minimal account state needed for commitment validation.
#[derive(Debug, Clone, Copy)]
pub struct AccountState {
    /// The nonce of the account. This is the number of transactions sent from this account
    /// and should be the
    pub transaction_count: u64,
    pub balance: U256,
}
