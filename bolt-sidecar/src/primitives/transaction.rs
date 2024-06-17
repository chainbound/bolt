use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, SignatureError, U256};

pub trait TxInfo {
    fn gas_price(&self) -> Option<u128>;
    fn max_fee_per_gas(&self) -> Option<u128>;
    fn max_priority_fee_per_gas(&self) -> Option<u128>;
    fn from(&self) -> Result<Address, SignatureError>;
    fn gas_limit(&self) -> u128;
    fn nonce(&self) -> u64;
    fn value(&self) -> U256;
    fn blob_count(&self) -> usize;
}

impl TxInfo for TxEnvelope {
    fn gas_price(&self) -> Option<u128> {
        match self {
            TxEnvelope::Legacy(tx) => Some(tx.tx().gas_price),
            TxEnvelope::Eip2930(tx) => Some(tx.tx().gas_price),
            TxEnvelope::Eip1559(_) => None,
            TxEnvelope::Eip4844(_) => None,
            _ => unimplemented!("TxEnvelope variant not supported"),
        }
    }

    fn max_fee_per_gas(&self) -> Option<u128> {
        match self {
            TxEnvelope::Legacy(_) => None,
            TxEnvelope::Eip2930(_) => None,
            TxEnvelope::Eip1559(tx) => Some(tx.tx().max_fee_per_gas),
            TxEnvelope::Eip4844(tx) => Some(tx.tx().tx().max_fee_per_gas),
            _ => unimplemented!("TxEnvelope variant not supported"),
        }
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        match self {
            TxEnvelope::Legacy(_) => None,
            TxEnvelope::Eip2930(_) => None,
            TxEnvelope::Eip1559(tx) => Some(tx.tx().max_priority_fee_per_gas),
            TxEnvelope::Eip4844(tx) => Some(tx.tx().tx().max_priority_fee_per_gas),
            _ => unimplemented!("TxEnvelope variant not supported"),
        }
    }

    fn from(&self) -> Result<Address, SignatureError> {
        self.recover_signer()
    }

    fn gas_limit(&self) -> u128 {
        match self {
            TxEnvelope::Legacy(tx) => tx.tx().gas_limit,
            TxEnvelope::Eip2930(tx) => tx.tx().gas_limit,
            TxEnvelope::Eip1559(tx) => tx.tx().gas_limit,
            TxEnvelope::Eip4844(tx) => tx.tx().tx().gas_limit,
            _ => unimplemented!("TxEnvelope variant not supported"),
        }
    }

    fn nonce(&self) -> u64 {
        match self {
            TxEnvelope::Legacy(tx) => tx.tx().nonce,
            TxEnvelope::Eip2930(tx) => tx.tx().nonce,
            TxEnvelope::Eip1559(tx) => tx.tx().nonce,
            TxEnvelope::Eip4844(tx) => tx.tx().tx().nonce,
            _ => unimplemented!("TxEnvelope variant not supported"),
        }
    }

    fn value(&self) -> U256 {
        match self {
            TxEnvelope::Legacy(tx) => tx.tx().value,
            TxEnvelope::Eip2930(tx) => tx.tx().value,
            TxEnvelope::Eip1559(tx) => tx.tx().value,
            TxEnvelope::Eip4844(tx) => tx.tx().tx().value,
            _ => unimplemented!("TxEnvelope variant not supported"),
        }
    }

    fn blob_count(&self) -> usize {
        match self {
            TxEnvelope::Legacy(_) => 0,
            TxEnvelope::Eip2930(_) => 0,
            TxEnvelope::Eip1559(_) => 0,
            TxEnvelope::Eip4844(tx) => tx.tx().tx().blob_versioned_hashes.len(),
            _ => unimplemented!("TxEnvelope variant not supported"),
        }
    }
}
