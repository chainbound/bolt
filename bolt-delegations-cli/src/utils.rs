use alloy::primitives::FixedBytes;
use ethereum_consensus::{
    crypto::PublicKey as BlsPublicKey,
    deneb::{compute_fork_data_root, compute_signing_root, Root},
};
use eyre::Result;

use crate::types::DelegationMessage;

// Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
pub const KEYSTORE_PASSWORD: &str = r#"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"#;

pub const COMMIT_BOOST_DOMAIN_MASK: [u8; 4] = [109, 109, 111, 67];

/// Parse the delegated public key from a string
pub fn parse_public_key(delegatee_pubkey: &str) -> Result<BlsPublicKey> {
    let hex_pk = delegatee_pubkey
        .strip_prefix("0x")
        .unwrap_or(delegatee_pubkey);
    BlsPublicKey::try_from(
        hex::decode(hex_pk)
            .expect("Failed to decode pubkey")
            .as_slice(),
    )
    .map_err(|e| eyre::eyre!("Failed to parse public key from string '{}': {}", hex_pk, e))
}

/// Helper function to compute the signing root for a delegation message
pub fn compute_signing_root_for_delegation(
    delegation: &DelegationMessage,
) -> Result<FixedBytes<32>> {
    let message = delegation.digest();
    compute_signing_root(&message, compute_domain_from_mask(COMMIT_BOOST_DOMAIN_MASK))
        .map_err(|e| eyre::eyre!("Failed to compute signing root: {}", e))
}

pub fn compute_domain_from_mask(mask: [u8; 4]) -> [u8; 32] {
    let mut domain = [0; 32];

    // Mainnet fork version
    let fork_version = [0, 0, 0, 0];

    // Note: the application builder domain specs require the genesis_validators_root
    // to be 0x00 for any out-of-protocol message. The commit-boost domain follows the
    // same rule.
    let root = Root::default();
    let fork_data_root = compute_fork_data_root(fork_version, root).expect("valid fork data");

    domain[..4].copy_from_slice(&mask);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}
