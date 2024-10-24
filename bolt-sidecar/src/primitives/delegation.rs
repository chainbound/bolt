use std::{fs, path::PathBuf};

use alloy::signers::k256::sha2::{Digest, Sha256};
use ethereum_consensus::crypto::{PublicKey as BlsPublicKey, Signature as BlsSignature};

use crate::crypto::SignableBLS;

/// Event types that can be emitted by the validator pubkey to
/// signal some action on the Bolt protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignedMessageAction {
    /// Signal delegation of a validator pubkey to a delegatee pubkey.
    Delegation,
    /// Signal revocation of a previously delegated pubkey.
    Revocation,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DelegationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

impl DelegationMessage {
    /// Create a new delegation message.
    pub fn new(validator_pubkey: BlsPublicKey, delegatee_pubkey: BlsPublicKey) -> Self {
        Self { action: SignedMessageAction::Delegation as u8, validator_pubkey, delegatee_pubkey }
    }
}

impl SignableBLS for DelegationMessage {
    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.to_vec());
        hasher.update(self.delegatee_pubkey.to_vec());

        hasher.finalize().into()
    }
}

/// read the delegations from disk if they exist and add them to the constraints client
pub fn read_signed_delegations_from_file(
    file_path: &PathBuf,
) -> eyre::Result<Vec<SignedDelegation>> {
    match fs::read_to_string(file_path) {
        Ok(contents) => match serde_json::from_str::<Vec<SignedDelegation>>(&contents) {
            Ok(delegations) => Ok(delegations),
            Err(err) => Err(eyre::eyre!("Failed to parse signed delegations from disk: {:?}", err)),
        },
        Err(err) => Err(eyre::eyre!("Failed to read signed delegations from disk: {:?}", err)),
    }
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct SignedRevocation {
    pub message: RevocationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct RevocationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

impl RevocationMessage {
    /// Create a new revocation message.
    pub fn new(validator_pubkey: BlsPublicKey, delegatee_pubkey: BlsPublicKey) -> Self {
        Self { action: SignedMessageAction::Revocation as u8, validator_pubkey, delegatee_pubkey }
    }
}

impl SignableBLS for RevocationMessage {
    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.to_vec());
        hasher.update(self.delegatee_pubkey.to_vec());

        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[test]
    fn test_read_signed_delegations_from_file() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("test_data/delegations.json");

        let delegations = super::read_signed_delegations_from_file(&path)
            .expect("Failed to read delegations from file");

        assert_eq!(delegations.len(), 1);
        assert_eq!(
            format!("{:?}", delegations[0].message.validator_pubkey), 
            "0x83b85769a8f2a1a6bd3a609e51b460f6fb897daff1157991479421493926faeffa6670152524403929a8a7e551d345f3"
        );
    }
}
