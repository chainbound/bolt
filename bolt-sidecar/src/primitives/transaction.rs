use std::borrow::Cow;

use alloy::primitives::{Address, U256};
use reth_primitives::{BlobTransactionSidecar, Bytes, PooledTransactionsElement, TxKind, TxType};
use serde::{de, ser::SerializeSeq};

/// Trait that exposes additional information on transaction types that don't already do it
/// by themselves (e.g. [`PooledTransactionsElement`]).
pub trait TransactionExt {
    fn gas_limit(&self) -> u64;
    fn value(&self) -> U256;
    fn tx_type(&self) -> TxType;
    fn tx_kind(&self) -> TxKind;
    fn input(&self) -> &Bytes;
    fn chain_id(&self) -> Option<u64>;
    fn blob_sidecar(&self) -> Option<&BlobTransactionSidecar>;
    fn size(&self) -> usize;
}

impl TransactionExt for PooledTransactionsElement {
    fn gas_limit(&self) -> u64 {
        match self {
            PooledTransactionsElement::Legacy { transaction, .. } => transaction.gas_limit,
            PooledTransactionsElement::Eip2930 { transaction, .. } => transaction.gas_limit,
            PooledTransactionsElement::Eip1559 { transaction, .. } => transaction.gas_limit,
            PooledTransactionsElement::BlobTransaction(blob_tx) => blob_tx.transaction.gas_limit,
            _ => unimplemented!(),
        }
    }

    fn value(&self) -> U256 {
        match self {
            PooledTransactionsElement::Legacy { transaction, .. } => transaction.value,
            PooledTransactionsElement::Eip2930 { transaction, .. } => transaction.value,
            PooledTransactionsElement::Eip1559 { transaction, .. } => transaction.value,
            PooledTransactionsElement::BlobTransaction(blob_tx) => blob_tx.transaction.value,
            _ => unimplemented!(),
        }
    }

    fn tx_type(&self) -> TxType {
        match self {
            PooledTransactionsElement::Legacy { .. } => TxType::Legacy,
            PooledTransactionsElement::Eip2930 { .. } => TxType::Eip2930,
            PooledTransactionsElement::Eip1559 { .. } => TxType::Eip1559,
            PooledTransactionsElement::BlobTransaction(_) => TxType::Eip4844,
            _ => unimplemented!(),
        }
    }

    fn tx_kind(&self) -> TxKind {
        match self {
            PooledTransactionsElement::Legacy { transaction, .. } => transaction.to,
            PooledTransactionsElement::Eip2930 { transaction, .. } => transaction.to,
            PooledTransactionsElement::Eip1559 { transaction, .. } => transaction.to,
            PooledTransactionsElement::BlobTransaction(blob_tx) => {
                TxKind::Call(blob_tx.transaction.to)
            }
            _ => unimplemented!(),
        }
    }

    fn input(&self) -> &Bytes {
        match self {
            PooledTransactionsElement::Legacy { transaction, .. } => &transaction.input,
            PooledTransactionsElement::Eip2930 { transaction, .. } => &transaction.input,
            PooledTransactionsElement::Eip1559 { transaction, .. } => &transaction.input,
            PooledTransactionsElement::BlobTransaction(blob_tx) => &blob_tx.transaction.input,
            _ => unimplemented!(),
        }
    }

    fn chain_id(&self) -> Option<u64> {
        match self {
            PooledTransactionsElement::Legacy { transaction, .. } => transaction.chain_id,
            PooledTransactionsElement::Eip2930 { transaction, .. } => Some(transaction.chain_id),
            PooledTransactionsElement::Eip1559 { transaction, .. } => Some(transaction.chain_id),
            PooledTransactionsElement::BlobTransaction(blob_tx) => {
                Some(blob_tx.transaction.chain_id)
            }
            _ => unimplemented!(),
        }
    }

    fn blob_sidecar(&self) -> Option<&BlobTransactionSidecar> {
        match self {
            PooledTransactionsElement::BlobTransaction(blob_tx) => Some(&blob_tx.sidecar),
            _ => None,
        }
    }

    fn size(&self) -> usize {
        match self {
            PooledTransactionsElement::Legacy { transaction, .. } => transaction.size(),
            PooledTransactionsElement::Eip2930 { transaction, .. } => transaction.size(),
            PooledTransactionsElement::Eip1559 { transaction, .. } => transaction.size(),
            PooledTransactionsElement::BlobTransaction(blob_tx) => blob_tx.transaction.size(),
            _ => unimplemented!(),
        }
    }
}

pub const fn tx_type_str(tx_type: TxType) -> &'static str {
    match tx_type {
        TxType::Legacy => "legacy",
        TxType::Eip2930 => "eip2930",
        TxType::Eip1559 => "eip1559",
        TxType::Eip4844 => "eip4844",
        TxType::Eip7702 => "eip7702",
    }
}

/// A wrapper type for a full, complete transaction (i.e. with blob sidecars attached).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullTransaction {
    pub tx: PooledTransactionsElement,
    pub sender: Option<Address>,
}

impl From<PooledTransactionsElement> for FullTransaction {
    fn from(tx: PooledTransactionsElement) -> Self {
        Self { tx, sender: None }
    }
}

impl std::ops::Deref for FullTransaction {
    type Target = PooledTransactionsElement;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl std::ops::DerefMut for FullTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

impl FullTransaction {
    /// Convenience method to parse a raw transaction into a `FullTransaction`.
    pub fn decode_enveloped(data: impl AsRef<[u8]>) -> eyre::Result<Self> {
        let tx = PooledTransactionsElement::decode_enveloped(&mut data.as_ref())?;
        Ok(Self { tx, sender: None })
    }

    pub fn into_inner(self) -> PooledTransactionsElement {
        self.tx
    }

    /// Returns the sender of the transaction, if recovered.
    pub fn sender(&self) -> Option<&Address> {
        self.sender.as_ref()
    }

    /// Returns the effective miner gas tip cap (`gasTipCap`) for the given base fee:
    /// `min(maxFeePerGas - baseFee, maxPriorityFeePerGas)`
    ///
    /// Returns `None` if the basefee is higher than the [`Transaction::max_fee_per_gas`].
    /// Ref: https://github.com/paradigmxyz/reth/blob/2d592125128c3742ff97b321884f93f9063abcb2/crates/primitives/src/transaction/mod.rs#L444
    pub fn effective_tip_per_gas(&self, base_fee: u128) -> Option<u128> {
        let max_fee_per_gas = self.max_fee_per_gas();

        if max_fee_per_gas < base_fee {
            return None;
        }

        // Calculate the difference between max_fee_per_gas and base_fee
        let fee = max_fee_per_gas - base_fee;

        // Compare the fee with max_priority_fee_per_gas (or gas price for non-EIP1559 transactions)
        if let Some(priority_fee) = self.max_priority_fee_per_gas() {
            Some(fee.min(priority_fee))
        } else {
            Some(fee)
        }
    }
}

/// Serialize a list of transactions into a sequence of hex-encoded strings.
pub fn serialize_txs<S: serde::Serializer>(
    txs: &[FullTransaction],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_seq(Some(txs.len()))?;
    for tx in txs {
        let encoded = tx.tx.envelope_encoded();
        seq.serialize_element(&format!("0x{}", hex::encode(encoded)))?;
    }
    seq.end()
}

/// Deserialize a list of transactions from a sequence of hex-encoded strings.
pub fn deserialize_txs<'de, D>(deserializer: D) -> Result<Vec<FullTransaction>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_strings = <Vec<Cow<'_, str>> as de::Deserialize>::deserialize(deserializer)?;
    let mut txs = Vec::with_capacity(hex_strings.len());

    for s in hex_strings {
        let data = hex::decode(s.trim_start_matches("0x")).map_err(de::Error::custom)?;
        let tx = PooledTransactionsElement::decode_enveloped(&mut data.as_slice())
            .map_err(de::Error::custom)
            .map(|tx| FullTransaction { tx, sender: None })?;
        txs.push(tx);
    }

    Ok(txs)
}
