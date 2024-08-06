use alloy::rpc::types::beacon::{constants::BLS_DST_SIG, BlsSignature};
use blst::{
    min_pk::{PublicKey, SecretKey},
    BLST_ERROR,
};
use ethereum_consensus::{
    crypto::Signature,
    deneb::{compute_fork_data_root, Domain, DomainType, Root},
    ssz::prelude::{HashTreeRoot, MerkleizationError},
};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::ChainConfig;

/// Sign a SSZ object with a BLS secret key, using the Application Builder domain
/// for signing arbitrary builder-api messages in the out-of-protocol specifications.
///
/// Fun Note: we use a `blst` secret key to sign a message, and produce an `alloy` signature,
/// which is then converted to an `ethereum-consensus` signature.
pub fn sign_builder_message<T: HashTreeRoot>(
    chain: &ChainConfig,
    sk: &SecretKey,
    msg: &T,
) -> Result<Signature, MerkleizationError> {
    let domain = chain.builder_domain();
    let object_root = msg.hash_tree_root()?.0;
    let signing_root = compute_signing_root(object_root, domain);

    let alloy_signature = sign_message(sk, &signing_root);
    let consensus_signature =
        Signature::try_from(alloy_signature.as_slice()).expect("valid signature bytes");

    Ok(consensus_signature)
}

/// Verify a SSZ object signed with a BLS public key, using the Application Builder domain
/// for signing arbitrary builder-api messages in the out-of-protocol specifications.
pub fn verify_signed_builder_message<T: HashTreeRoot>(
    chain: &ChainConfig,
    pubkey: &PublicKey,
    msg: &T,
    signature: &BlsSignature,
) -> Result<(), ethereum_consensus::Error> {
    let domain = chain.builder_domain();
    let object_root = msg.hash_tree_root()?.0;
    let signing_root = compute_signing_root(object_root, domain);

    verify_signature(pubkey, &signing_root, signature).map_err(|_| {
        ethereum_consensus::Error::Bls(ethereum_consensus::crypto::BlsError::InvalidSignature)
    })
}

/// Verify a BLS signature for a given message and public key.
pub fn verify_signature(
    pubkey: &PublicKey,
    msg: &[u8],
    signature: &BlsSignature,
) -> Result<(), blst::BLST_ERROR> {
    let sig = blst::min_pk::Signature::from_bytes(&signature.0).expect("valid signature bytes");

    let res = sig.verify(true, msg, BLS_DST_SIG, &[], pubkey, true);
    if res == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(res)
    }
}

/// Sign arbitrary bytes with a BLS secret key, using the BLS DST signature domain,
/// as defined in the Ethereum 2.0 specification. It stands for "Domain Separation Tag
/// for hash_to_point in Ethereum beacon chain BLS12-381 signatures".
pub fn sign_message(secret_key: &SecretKey, msg: &[u8]) -> BlsSignature {
    let signature = secret_key.sign(msg, BLS_DST_SIG, &[]).to_bytes();
    BlsSignature::from_slice(&signature)
}

/// Helper struct to compute the signing root for a given object
/// root and signing domain as defined in the Ethereum 2.0 specification.
#[derive(Default, Debug, TreeHash)]
struct SigningData {
    object_root: [u8; 32],
    signing_domain: [u8; 32],
}

/// Compute the signing root for a given object root and signing domain.
pub fn compute_signing_root(object_root: [u8; 32], signing_domain: [u8; 32]) -> [u8; 32] {
    let signing_data = SigningData { object_root, signing_domain };
    signing_data.tree_hash_root().0
}

/// Compute the Application Builder domain for signing arbitrary
/// builder-api messages in the out-of-protocol specifications
///
/// Docs: <https://github.com/ethereum/builder-specs/blob/982af908707113de373e62babee113782e6bb6cd/specs/bellatrix/builder.md#signing>
#[allow(dead_code)]
pub fn compute_builder_domain(
    fork_version: [u8; 4],
    genesis_validators_root: Option<[u8; 32]>,
) -> [u8; 32] {
    // The builder-specs require the genesis_validators_root to be 0x00
    // for any out-of-protocol message. Here we leave the option to set
    // it to a custom value if any devnet violates this rule.
    let root = genesis_validators_root.map_or(Root::default(), |root| Root::from_slice(&root));

    let fork_data_root = compute_fork_data_root(fork_version, root).expect("valid fork data");

    // Also known as `DOMAIN_APPLICATION_BUILDER` in the specs
    let domain_type = DomainType::ApplicationBuilder;

    let mut domain = Domain::default();
    domain[..4].copy_from_slice(&domain_type.as_bytes());
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

#[cfg(test)]
mod tests {
    use crate::{builder::signature::compute_builder_domain, ChainConfig};

    #[test]
    fn test_compute_builder_domain() {
        let mainnet = ChainConfig::mainnet();
        assert_eq!(compute_builder_domain(mainnet.fork_version(), None), mainnet.builder_domain());

        let holesky = ChainConfig::holesky();
        assert_eq!(compute_builder_domain(holesky.fork_version(), None), holesky.builder_domain());

        let kurtosis = ChainConfig::kurtosis(0, 0);
        assert_eq!(
            compute_builder_domain(kurtosis.fork_version(), None),
            kurtosis.builder_domain()
        );

        let helder = ChainConfig::helder();
        assert_eq!(compute_builder_domain(helder.fork_version(), None), helder.builder_domain());
    }
}
