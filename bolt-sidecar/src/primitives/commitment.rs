use serde::{de, Deserialize, Deserializer, Serialize};
use std::str::FromStr;

use alloy::primitives::{keccak256, Signature, B256};

use super::{FullTransaction, TransactionExt};

/// Commitment requests sent by users or RPC proxies to the sidecar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CommitmentRequest {
    /// Request of inclusion of a transaction at a specific slot.
    Inclusion(InclusionRequest),
}

/// A signed commitment with a generic signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Commitment {
    Inclusion(InclusionCommitment),
}

/// A signed inclusion commitment with a generic signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionCommitment {
    request: InclusionRequest,
    #[serde(deserialize_with = "deserialize_sig", serialize_with = "serialize_sig")]
    signature: Signature,
}

impl From<Commitment> for InclusionCommitment {
    fn from(commitment: Commitment) -> Self {
        match commitment {
            Commitment::Inclusion(inclusion) => inclusion,
        }
    }
}

impl CommitmentRequest {
    /// Returns a reference to the inner request if this is an inclusion request, otherwise `None`.
    pub fn as_inclusion_request(&self) -> Option<&InclusionRequest> {
        match self {
            CommitmentRequest::Inclusion(req) => Some(req),
            // TODO: remove this when we have more request types
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

/// Request to include a transaction at a specific slot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionRequest {
    /// The consensus slot number at which the transaction should be included.
    pub slot: u64,
    /// The transaction to be included.
    pub txs: Vec<FullTransaction>,
    /// The signature over the "slot" and "tx" fields by the user.
    /// A valid signature is the only proof that the user actually requested
    /// this specific commitment to be included at the given slot.
    #[serde(skip)]
    pub signature: Option<Signature>,
}

impl InclusionRequest {
    /// Validates the transaction fees against a minimum basefee.
    /// Returns true if the fee is greater than or equal to the min, false otherwise.
    pub fn validate_basefee(&self, min: u128) -> bool {
        for tx in &self.txs {
            if tx.max_fee_per_gas() < min {
                return false;
            }
        }

        true
    }

    /// Validates the transaction chain id against the provided chain id.
    /// Returns true if the chain id matches, false otherwise. Will always return true
    /// for pre-EIP155 transactions.
    pub fn validate_chain_id(&self, chain_id: u64) -> bool {
        for tx in &self.txs {
            // Check if pre-EIP155 transaction
            if let Some(id) = tx.chain_id() {
                if id != chain_id {
                    return false;
                }
            }
        }

        true
    }

    /// Sets the signature.
    pub fn set_signature(&mut self, signature: Signature) {
        self.signature = Some(signature);
    }

    pub fn recover_signers(&mut self) -> Result<(), SignatureError> {
        for tx in &mut self.txs {
            let signer = tx.recover_signer().ok_or(SignatureError)?;
            tx.sender = Some(signer);
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid signature")]
struct SignatureError;

fn deserialize_sig<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(s.trim_start_matches("0x")).map_err(de::Error::custom)
}

fn serialize_sig<S: serde::Serializer>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error> {
    let parity = sig.v();
    // As bytes encodes the parity as 27/28, need to change that.
    let mut bytes = sig.as_bytes();
    bytes[bytes.len() - 1] = if parity.y_parity() { 1 } else { 0 };
    serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
}

impl InclusionRequest {
    /// Returns the digest of the request.
    /// digest = keccak256(bytes(tx_hash1) | bytes(tx_hash2) | ... | le_bytes(target_slot))
    pub fn digest(&self) -> B256 {
        let mut data = Vec::new();
        // First field is the concatenation of all the transaction hashes
        data.extend_from_slice(
            &self
                .txs
                .iter()
                .map(|tx| tx.hash().as_slice())
                .collect::<Vec<_>>()
                .concat(),
        );

        // Second field is the little endian encoding of the target slot
        data.extend_from_slice(&self.slot.to_le_bytes());

        keccak256(&data)
    }
}

impl From<InclusionRequest> for CommitmentRequest {
    fn from(req: InclusionRequest) -> Self {
        CommitmentRequest::Inclusion(req)
    }
}

pub trait ECDSASignatureExt {
    /// Returns the ECDSA signature as bytes with the correct parity bit.
    fn as_bytes_with_parity(&self) -> [u8; 65];
    /// Rethrns the ECDSA signature as a 0x-prefixed hex string with the correct parity bit.
    fn to_hex(&self) -> String;
}

impl ECDSASignatureExt for Signature {
    fn as_bytes_with_parity(&self) -> [u8; 65] {
        let parity = self.v();
        // As bytes encodes the parity as 27/28, need to change that.
        let mut bytes = self.as_bytes();
        bytes[bytes.len() - 1] = if parity.y_parity() { 1 } else { 0 };

        bytes
    }

    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.as_bytes_with_parity()))
    }
}

#[cfg(test)]
mod tests {
    use super::{CommitmentRequest, InclusionRequest};

    #[test]
    fn test_deserialize_inclusion_request() {
        let json_req = r#"{
            "tx": "0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4",
            "signature": "0xb8623aae262785bd31d0cc6e368a9b9ab5361002edd58ece424ef5dde0544b32472d954da3f34ca9c2c2201393f9b83cdc959bd416c0af96fe3e0962a08cb92101",
            "slot": 1
        }"#;

        let req: InclusionRequest = serde_json::from_str(json_req).unwrap();
        assert_eq!(req.slot, 1);

        let deser = serde_json::to_string(&req).unwrap();

        assert_eq!(
            deser.parse::<serde_json::Value>().unwrap(),
            json_req.parse::<serde_json::Value>().unwrap()
        );
    }

    #[test]
    fn test_deserialize_commitment_request() {
        let json_req = r#"{
            "tx": "0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4",
            "signature": "0xb8623aae262785bd31d0cc6e368a9b9ab5361002edd58ece424ef5dde0544b32472d954da3f34ca9c2c2201393f9b83cdc959bd416c0af96fe3e0962a08cb92101",
            "slot": 1
        }"#;

        let req: CommitmentRequest = serde_json::from_str(json_req).unwrap();

        #[allow(irrefutable_let_patterns)]
        if let CommitmentRequest::Inclusion(req) = req {
            assert_eq!(req.slot, 1);
        } else {
            panic!("Expected Inclusion request");
        }
    }
}
