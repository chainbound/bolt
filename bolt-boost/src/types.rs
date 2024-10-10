use alloy::{
    consensus::{TxEip4844Variant, TxEnvelope},
    eips::eip2718::{Decodable2718, Eip2718Error, Eip2718Result},
    primitives::{Bytes, TxHash, B256},
    rpc::types::beacon::{BlsPublicKey, BlsSignature},
    signers::k256::sha2::{Digest, Sha256},
};
use alloy_rlp::{BufMut, Encodable};
use axum::http::HeaderMap;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::ops::Deref;
use tracing::error;

use cb_common::{
    constants::COMMIT_BOOST_DOMAIN,
    pbs::{DenebSpec, EthSpec, SignedExecutionPayloadHeader, Transaction, VersionedResponse},
    signature::{compute_domain, compute_signing_root},
    signer::schemes::bls::verify_bls_signature,
    types::Chain,
};

/// A hash tree root.
pub type HashTreeRoot = tree_hash::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct GetHeaderParams {
    pub slot: u64,
    pub parent_hash: B256,
    pub pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedConstraints {
    pub message: ConstraintsMessage,
    pub signature: BlsSignature,
}

impl SignedConstraints {
    /// Verifies the signature on this message against the provided BLS public key.
    /// The `chain` and `COMMIT_BOOST_DOMAIN` are used to compute the signing root.
    #[allow(unused)]
    pub fn verify_signature(&self, chain: Chain, pubkey: &BlsPublicKey) -> bool {
        let domain = compute_domain(chain, COMMIT_BOOST_DOMAIN);
        let digest = match self.message.digest() {
            Ok(digest) => digest,
            Err(e) => {
                error!(err = ?e, "Failed to compute digest");
                return false;
            }
        };

        let signing_root = compute_signing_root(digest, domain);
        verify_bls_signature(pubkey, &signing_root, &self.signature).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq, Deserialize, Encode, Decode)]
pub struct ConstraintsMessage {
    pub pubkey: BlsPublicKey,
    pub slot: u64,
    pub top: bool,
    pub transactions: Vec<Bytes>,
}

impl ConstraintsMessage {
    /// Returns the digest of this message.
    pub fn digest(&self) -> Eip2718Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(self.pubkey);
        hasher.update(self.slot.to_le_bytes());
        hasher.update((self.top as u8).to_le_bytes());

        for bytes in &self.transactions {
            let tx = TxEnvelope::decode_2718(&mut bytes.as_ref())?;
            hasher.update(tx.tx_hash());
        }

        Ok(hasher.finalize().into())
    }
}

#[derive(Debug)]
pub struct ConstraintsWithProofData {
    pub message: ConstraintsMessage,
    /// List of transaction hashes and corresponding hash tree roots. Same order
    /// as the transactions in the `message`.
    pub proof_data: Vec<(TxHash, HashTreeRoot)>,
}

impl TryFrom<ConstraintsMessage> for ConstraintsWithProofData {
    type Error = Eip2718Error;

    fn try_from(value: ConstraintsMessage) -> Result<Self, Self::Error> {
        let transactions = value
            .transactions
            .iter()
            .map(|tx| {
                let envelope = TxEnvelope::decode_2718(&mut tx.as_ref())?;
                let tx_hash_tree_root = calculate_tx_hash_tree_root(&envelope, tx)?;

                Ok((*envelope.tx_hash(), tx_hash_tree_root))
            })
            .collect::<Result<Vec<_>, Eip2718Error>>()?;

        Ok(Self { message: value, proof_data: transactions })
    }
}

/// Calculate the SSZ hash tree root of a transaction, starting from its enveloped form.
/// For type 3 transactions, the hash tree root of the inner transaction is taken (without blobs).
fn calculate_tx_hash_tree_root(
    envelope: &TxEnvelope,
    raw_tx: &Bytes,
) -> Result<B256, Eip2718Error> {
    match envelope {
        // For type 3 txs, take the hash tree root of the inner tx (EIP-4844)
        TxEnvelope::Eip4844(tx) => match tx.tx() {
            TxEip4844Variant::TxEip4844(tx) => {
                let mut out = Vec::new();
                out.put_u8(0x03);
                tx.encode(&mut out);

                Ok(tree_hash::TreeHash::tree_hash_root(&Transaction::<
                    <DenebSpec as EthSpec>::MaxBytesPerTransaction,
                >::from(out)))
            }
            TxEip4844Variant::TxEip4844WithSidecar(tx) => {
                use alloy_rlp::Encodable;
                let mut out = Vec::new();
                out.put_u8(0x03);
                tx.tx.encode(&mut out);

                Ok(tree_hash::TreeHash::tree_hash_root(&Transaction::<
                    <DenebSpec as EthSpec>::MaxBytesPerTransaction,
                >::from(out)))
            }
        },
        // For other transaction types, take the hash tree root of the whole tx
        _ => Ok(tree_hash::TreeHash::tree_hash_root(&Transaction::<
            <DenebSpec as EthSpec>::MaxBytesPerTransaction,
        >::from(raw_tx.to_vec()))),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct DelegationMessage {
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedRevocation {
    pub message: RevocationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct RevocationMessage {
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

pub type GetHeaderWithProofsResponse = VersionedResponse<SignedExecutionPayloadHeaderWithProofs>;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedExecutionPayloadHeaderWithProofs {
    #[serde(flatten)]
    pub header: SignedExecutionPayloadHeader,
    #[serde(default)]
    pub proofs: InclusionProofs,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct InclusionProofs {
    /// The transaction hashes these inclusion proofs are for. The hash tree roots of
    /// these transactions are the leaves of the transactions tree.
    pub transaction_hashes: Vec<TxHash>,
    /// The generalized indeces of the nodes in the transactions tree.
    pub generalized_indeces: Vec<usize>,
    /// The proof hashes for the transactions tree.
    pub merkle_hashes: Vec<B256>,
}

impl InclusionProofs {
    /// Returns the total number of leaves in the tree.
    pub fn total_leaves(&self) -> usize {
        self.transaction_hashes.len()
    }
}

impl Deref for SignedExecutionPayloadHeaderWithProofs {
    type Target = SignedExecutionPayloadHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

#[derive(Debug)]
pub struct RequestConfig {
    pub url: Url,
    pub timeout_ms: u64,
    pub headers: HeaderMap,
}

#[cfg(test)]
mod tests {
    use alloy::{hex::FromHex, primitives::Bytes};

    use super::ConstraintsWithProofData;
    use crate::types::SignedConstraints;

    #[test]
    fn decode_constraints_test() {
        let raw = r#"{
            "message": {
                "pubkey": "0xa695ad325dfc7e1191fbc9f186f58eff42a634029731b18380ff89bf42c464a42cb8ca55b200f051f57f1e1893c68759",
                "slot": 32,
                "top": true,
                "transactions": [
                    "0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4"
                ]
            },
		    "signature": "0xb8d50ee0d4b269db3d4658c1dac784d273a4160d769e16dce723a9684c390afe5865348416b3bf0f1a4f47098bec9024135d0d95f08bed18eb577a3d8a67f5dc78b13cc62515e280786a73fb267d35dfb7ab46a25ac29bf5bc2fa5b07b3e07a6"
		}"#;

        let mut c = serde_json::from_str::<SignedConstraints>(raw).unwrap();
        let pd = ConstraintsWithProofData::try_from(c.message.clone()).unwrap().proof_data[0];

        assert_eq!(
            pd.0.to_string(),
            "0x385b9f1ba5dbbe419dcbbbbf0840b76b941f3c216d383ec9deb9b1a323ee0cea".to_string()
        );

        assert_eq!(
            pd.1.to_string(),
            "0x02e383af0c34516ef38e13391d917d5b61b6f69e17d5234f77cb8cc3a1ae932e".to_string()
        );

        c.message.transactions[0] = Bytes::from_hex("0x03f9029c01830299f184b2d05e008507aef40a00832dc6c09468d30f47f19c07bccef4ac7fae2dc12fca3e0dc980b90204ef16e845000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000633b68f5d8d3a86593ebb815b4663bcbe0302e31382e302d64657600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004109de8da2a97e37f2e6dc9f7d50a408f9344d7aa1a925ae53daf7fbef43491a571960d76c0cb926190a9da10df7209fb1ba93cd98b1565a3a2368749d505f90c81c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0843b9aca00e1a00141e3a338e30c49ed0501e315bcc45e4edefebed43ab1368a1505461d9cf64901a01e8511e06b17683d89eb57b9869b96b8b611f969f7f56cbc0adc2df7c88a2a07a00910deacf91bba0d74e368d285d311dc5884e7cfe219d85aea5741b2b6e3a2fe").unwrap();

        let pd = ConstraintsWithProofData::try_from(c.message).unwrap().proof_data[0];

        assert_eq!(
            pd.0.to_string(),
            "0x15bd881daa1408b33f67fa4bdeb8acfb0a2289d9b4c6f81eef9bb2bb2e52e780".to_string()
        );

        assert_eq!(
            pd.1.to_string(),
            "0x0a637924b9f9b28a413b01cb543bcd688850b8964f77576fc71219448f7b4ab9".to_string()
        );
    }
}
