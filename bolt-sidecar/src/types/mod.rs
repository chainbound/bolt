use alloy_primitives::U256;

pub mod commitment;
pub mod transaction;

/// An alias for a Beacon Chain slot number
pub type Slot = u64;

/// Minimal account state needed for commitment validation.
#[derive(Debug, Clone, Copy)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
}
