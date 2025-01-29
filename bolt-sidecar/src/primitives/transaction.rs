use alloy::{
    consensus::{
        transaction::PooledTransaction, BlobTransactionSidecar, Signed, Transaction, TxType,
        Typed2718,
    },
    eips::eip2718::{Decodable2718, Encodable2718},
    hex,
    primitives::Address,
};
use reth_primitives::TransactionSigned;
use serde::{de, ser::SerializeSeq};
use std::{borrow::Cow, fmt};

/// Trait that exposes additional information on transaction types that don't already do it
/// by themselves (e.g. [`PooledTransaction`]).
pub trait TransactionExt {
    /// Returns the blob sidecar of the transaction, if any.
    fn blob_sidecar(&self) -> Option<&BlobTransactionSidecar>;

    /// Returns the size of the transaction in bytes.
    fn size(&self) -> usize;
}

impl TransactionExt for PooledTransaction {
    fn blob_sidecar(&self) -> Option<&BlobTransactionSidecar> {
        match self {
            Self::Eip4844(transaction) => Some(&transaction.tx().sidecar),
            _ => None,
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::Legacy(transaction) => transaction.tx().size(),
            Self::Eip1559(transaction) => transaction.tx().size(),
            Self::Eip2930(transaction) => transaction.tx().size(),
            Self::Eip4844(blob_tx) => blob_tx.tx().tx().size(),
            Self::Eip7702(transaction) => transaction.tx().size(),
        }
    }
}

/// Returns a string representation of the transaction type.
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
#[derive(Clone, PartialEq, Eq)]
pub struct FullTransaction {
    /// The transaction itself.
    pub tx: PooledTransaction,
    /// The sender of the transaction, if recovered.
    pub sender: Option<Address>,
}

impl From<PooledTransaction> for FullTransaction {
    fn from(tx: PooledTransaction) -> Self {
        Self { tx, sender: None }
    }
}

impl fmt::Debug for FullTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("FullTransaction");

        if self.tx.is_eip4844() {
            if let Some(tx) = self.tx.as_eip4844_with_sidecar() {
                let sidecar = tx.sidecar();

                let shortened_blobs: Vec<String> =
                    // Use alternative `Display` to print trimmed blob
                    sidecar.blobs.iter().map(|blob| format!("{blob:#}")).collect();

                debug_struct
                    .field("tx", &"BlobTransaction")
                    .field("hash", self.tx.hash())
                    .field("transaction", &tx.tx())
                    .field("signature", &self.tx.signature())
                    .field("sidecar_blobs", &shortened_blobs)
                    .field("sidecar_commitments", &sidecar.commitments)
                    .field("sidecar_proofs", &sidecar.proofs);
            } else {
                // Blob transaction without sidecar
                debug_struct
                    .field("tx", &"EIP-4844 Transaction (no sidecar)")
                    .field("hash", self.tx.hash());
            }
        }

        // Non-blob transactions, just for debug
        debug_struct.field("sender", &self.sender);
        debug_struct.finish()
    }
}

impl std::ops::Deref for FullTransaction {
    type Target = PooledTransaction;

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
        let tx = PooledTransaction::decode_2718(&mut data.as_ref())?;
        Ok(Self { tx, sender: None })
    }

    /// Returns the inner transaction.
    pub fn into_inner(self) -> PooledTransaction {
        self.tx
    }

    /// Returns the signed transaction.
    pub fn into_signed(self) -> TransactionSigned {
        match self.tx {
            PooledTransaction::Legacy(tx) => tx.into(),
            PooledTransaction::Eip1559(tx) => tx.into(),
            PooledTransaction::Eip2930(tx) => tx.into(),
            PooledTransaction::Eip4844(tx) => {
                let sig = *tx.signature();
                let hash = *tx.hash();
                let inner_tx = tx.into_parts().0.into_parts().0;
                Signed::new_unchecked(inner_tx, sig, hash).into()
            }
            PooledTransaction::Eip7702(tx) => tx.into(),
        }
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
        let encoded = tx.tx.encoded_2718();
        seq.serialize_element(&hex::encode_prefixed(encoded))?;
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
        let tx = PooledTransaction::decode_2718(&mut data.as_slice())
            .map_err(de::Error::custom)
            .map(|tx| FullTransaction { tx, sender: None })?;
        txs.push(tx);
    }

    Ok(txs)
}
