use serde::{de, Deserialize, Deserializer, Serialize};
use std::str::FromStr;

use alloy_primitives::{keccak256, Signature, B256};
use reth_primitives::PooledTransactionsElement;

/// Commitment requests sent by users or RPC proxies to the sidecar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CommitmentRequest {
    /// Request of inclusion of a transaction at a specific slot.
    Inclusion(InclusionRequest),
}

/// Request to include a transaction at a specific slot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionRequest {
    /// The consensus slot number at which the transaction should be included.
    pub slot: u64,
    /// The transaction to be included.
    #[serde(deserialize_with = "deserialize_tx", serialize_with = "serialize_tx")]
    pub tx: PooledTransactionsElement,
    /// The signature over the "slot" and "tx" fields by the user.
    /// A valid signature is the only proof that the user actually requested
    /// this specific commitment to be included at the given slot.
    #[serde(
        deserialize_with = "deserialize_from_str",
        serialize_with = "signature_as_str"
    )]
    pub signature: Signature,
}

impl InclusionRequest {
    /// Validates the transaction fee against a minimum basefee.
    /// Returns true if the fee is greater than or equal to the min, false otherwise.
    pub fn validate_basefee(&self, min: u128) -> bool {
        self.tx.max_fee_per_gas() >= min
    }
}

fn deserialize_tx<'de, D>(deserializer: D) -> Result<PooledTransactionsElement, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let data = hex::decode(s.trim_start_matches("0x")).map_err(de::Error::custom)?;
    PooledTransactionsElement::decode_enveloped(&mut data.as_slice()).map_err(de::Error::custom)
}

fn serialize_tx<S>(tx: &PooledTransactionsElement, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut data = Vec::new();
    tx.encode_enveloped(&mut data);
    serializer.serialize_str(&format!("0x{}", hex::encode(&data)))
}

fn deserialize_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(s.trim_start_matches("0x")).map_err(de::Error::custom)
}

fn signature_as_str<S: serde::Serializer>(
    sig: &Signature,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let parity = sig.v();
    // As bytes encodes the parity as 27/28, need to change that.
    let mut bytes = sig.as_bytes();
    bytes[bytes.len() - 1] = if parity.y_parity() { 1 } else { 0 };
    serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
}

impl InclusionRequest {
    /// TODO: actually use SSZ encoding here
    pub fn digest(&self) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(&self.slot.to_le_bytes());
        data.extend_from_slice(self.tx.hash().as_slice());

        keccak256(&data)
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
