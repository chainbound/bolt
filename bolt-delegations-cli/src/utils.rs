use ethereum_consensus::deneb::{compute_fork_data_root, Root};

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
