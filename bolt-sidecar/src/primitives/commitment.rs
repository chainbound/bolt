use serde::{de, Deserialize, Deserializer, Serialize};
use std::str::FromStr;

use alloy::primitives::{keccak256, Address, Signature, B256};

use crate::{
    crypto::SignerECDSA,
    primitives::{deserialize_txs, serialize_txs},
};

use super::{FullTransaction, SignatureError, TransactionExt};

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
pub enum SignedCommitment {
    Inclusion(InclusionCommitment),
}

/// A signed inclusion commitment with a generic signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionCommitment {
    #[serde(flatten)]
    request: InclusionRequest,
    #[serde(deserialize_with = "deserialize_sig", serialize_with = "serialize_sig")]
    signature: Signature,
}

impl From<SignedCommitment> for InclusionCommitment {
    fn from(commitment: SignedCommitment) -> Self {
        match commitment {
            SignedCommitment::Inclusion(inclusion) => inclusion,
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

    /// Commits and signs the request with the provided signer. Returns a [SignedCommitment].
    pub async fn commit_and_sign<S: SignerECDSA>(
        self,
        signer: &S,
    ) -> eyre::Result<SignedCommitment> {
        match self {
            CommitmentRequest::Inclusion(req) => {
                let digest = req.digest();
                let signature = signer.sign_hash(&digest).await?;
                Ok(SignedCommitment::Inclusion(InclusionCommitment { request: req, signature }))
            }
        }
    }

    /// Returns the signature (if signed).
    pub fn signature(&self) -> Option<&Signature> {
        match self {
            CommitmentRequest::Inclusion(req) => req.signature.as_ref(),
        }
    }
}

/// Request to include a transaction at a specific slot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionRequest {
    /// The consensus slot number at which the transaction should be included.
    pub slot: u64,
    /// The transaction to be included.
    #[serde(deserialize_with = "deserialize_txs", serialize_with = "serialize_txs")]
    pub txs: Vec<FullTransaction>,
    /// The signature over the "slot" and "tx" fields by the user.
    /// A valid signature is the only proof that the user actually requested
    /// this specific commitment to be included at the given slot.
    #[serde(skip)]
    pub signature: Option<Signature>,
    #[serde(skip)]
    pub signer: Option<Address>,
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

    /// Validates the tx size limit.
    pub fn validate_tx_size_limit(&self, limit: usize) -> bool {
        for tx in &self.txs {
            if tx.size() > limit {
                return false;
            }
        }

        true
    }

    /// Validates the init code limit.
    pub fn validate_init_code_limit(&self, limit: usize) -> bool {
        for tx in &self.txs {
            if tx.tx_kind().is_create() && tx.input().len() > limit {
                return false;
            }
        }

        true
    }

    pub fn validate_priority_fee(&self) -> bool {
        for tx in &self.txs {
            if tx
                .max_priority_fee_per_gas()
                .is_some_and(|max_priority_fee| max_priority_fee > tx.max_fee_per_gas())
            {
                return false;
            }
        }

        true
    }

    /// Returns the total gas limit of all transactions in this request.
    pub fn gas_limit(&self) -> u64 {
        self.txs.iter().map(|tx| tx.gas_limit()).sum()
    }

    /// Returns the transaction signer.
    pub fn signer(&self) -> Option<Address> {
        self.signer
    }

    /// Sets the signature.
    pub fn set_signature(&mut self, signature: Signature) {
        self.signature = Some(signature);
    }

    /// Sets the signer.
    pub fn set_signer(&mut self, signer: Address) {
        self.signer = Some(signer);
    }

    pub fn recover_signers(&mut self) -> Result<(), SignatureError> {
        for tx in &mut self.txs {
            let signer = tx.recover_signer().ok_or(SignatureError)?;
            tx.sender = Some(signer);
        }

        Ok(())
    }
}

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
            &self.txs.iter().map(|tx| tx.hash().as_slice()).collect::<Vec<_>>().concat(),
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
    use std::str::FromStr;

    use alloy::{
        hex,
        primitives::{Address, Signature},
    };

    use super::{CommitmentRequest, InclusionRequest};

    #[test]
    fn test_create_digest() {
        let json_req = r#"{
            "slot": 633067,
            "txs": ["0xf86b82016e84042343e0830f424094deaddeaddeaddeaddeaddeaddeaddeaddeaddead0780850344281a21a0e525fc31b5574722ff064bdd127c4441b0fc66de7dc44928e163cb68e9d807e5a00b3ec02fc1e34b0209f252369ad10b745cd5a51c88384a340f7a150d0e45e471"]
        }"#;

        let req: InclusionRequest = serde_json::from_str(json_req).unwrap();
        let digest = req.digest();
        assert_eq!(
            hex::encode(digest.as_slice()),
            "52ecc7832625c3d107aaba5b55d4509b48cd9f4f7ce375d6696d09bbf3310525"
        );

        // Verify signature over the digest
        let sig = Signature::from_str("0xcdd20b2abbd8cdfb77ec2608e1227f8ce0f66133b9d0ec0ea68102c2152b82193e3be0d6967b7c20b83e1a2530daa3a07713556541dc2aa16a46d922e6145a2b01").unwrap();
        let recovered = sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(
            recovered,
            Address::from_str("0x27083ED52464625660f3e30Aa5B9C20A30D7E110").unwrap()
        );
    }

    #[test]
    fn test_deserialize_inclusion_request() {
        let json_req = r#"{
            "slot": 10,
            "txs": ["0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4"]
        }"#;

        let req: InclusionRequest = serde_json::from_str(json_req).unwrap();
        assert_eq!(req.slot, 10);

        let deser = serde_json::to_string(&req).unwrap();

        assert_eq!(
            deser.parse::<serde_json::Value>().unwrap(),
            json_req.parse::<serde_json::Value>().unwrap()
        );
    }

    #[test]
    fn test_deserialize_commitment_request() {
        let json_req = r#"{
            "slot": 10,
            "txs": ["0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4"]
        }"#;

        let req: CommitmentRequest = serde_json::from_str(json_req).unwrap();

        #[allow(irrefutable_let_patterns)]
        if let CommitmentRequest::Inclusion(req) = req {
            assert_eq!(req.slot, 10);
        } else {
            panic!("Expected Inclusion request");
        }
    }
}
