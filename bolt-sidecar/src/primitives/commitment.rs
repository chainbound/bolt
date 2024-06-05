use std::str::FromStr;

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::Signature;
use serde::{de, Deserialize, Deserializer, Serialize};

use super::transaction::TxInfo;

/// Commitment requests sent by users or RPC proxies to the sidecar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CommitmentRequest {
    /// Request of inclusion of a transaction at a specific slot.
    Inclusion(InclusionRequest),
}

impl CommitmentRequest {
    pub fn as_inclusion_request(&self) -> Option<&InclusionRequest> {
        #[allow(irrefutable_let_patterns)] // TODO: remove when we add more variants
        if let CommitmentRequest::Inclusion(req) = self {
            Some(req)
        } else {
            None
        }
    }
}

/// Request to include a transaction at a specific slot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionRequest {
    /// The consensus slot number at which the transaction should be included.
    pub slot: u64,
    /// The transaction to be included.
    #[serde(deserialize_with = "deserialize_tx_envelope")]
    pub tx: TxEnvelope,
    /// The signature over the "slot" and "tx" fields by the user.
    /// A valid signature is the only proof that the user actually requested
    /// this specific commitment to be included at the given slot.
    #[serde(deserialize_with = "deserialize_from_str")]
    pub signature: Signature,
}

impl InclusionRequest {
    /// Validates the transaction fee against a minimum basefee.
    /// Returns true if the fee is greater than or equal to the min, false otherwise.
    pub fn validate_basefee(&self, min: u128) -> bool {
        if let Some(max_fee) = self.tx.max_fee_per_gas() {
            if max_fee < min {
                return false;
            }
        } else if let Some(fee) = self.tx.gas_price() {
            if fee < min {
                return false;
            }
        } else {
            unreachable!("Transaction must have a fee");
        }

        true
    }
}

fn deserialize_tx_envelope<'de, D>(deserializer: D) -> Result<TxEnvelope, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let s = hex::decode(s.trim_start_matches("0x")).map_err(de::Error::custom)?;
    TxEnvelope::decode_2718(&mut s.as_slice()).map_err(de::Error::custom)
}

fn deserialize_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(de::Error::custom)
}

impl InclusionRequest {
    // TODO: actually use SSZ encoding here
    pub fn digest(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(self.tx.tx_hash().as_slice());
        data
    }
}

impl From<InclusionRequest> for CommitmentRequest {
    fn from(req: InclusionRequest) -> Self {
        CommitmentRequest::Inclusion(req)
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
