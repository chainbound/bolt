use core::fmt;
use std::{fmt::Display, time::Duration};

use clap::{Args, ValueEnum};
use ethereum_consensus::deneb::{compute_fork_data_root, Root};
use serde::Deserialize;

/// Default commitment deadline duration.
///
/// The sidecar will stop accepting new commitments for the next block
/// after this deadline has passed. This is to ensure that builders and
/// relays have enough time to build valid payloads.
pub const DEFAULT_COMMITMENT_DEADLINE_IN_MILLIS: u64 = 8_000;

/// Default slot time duration in seconds.
pub const DEFAULT_SLOT_TIME_IN_SECONDS: u64 = 12;

/// The domain mask for signing application-builder messages.
pub const APPLICATION_BUILDER_DOMAIN_MASK: [u8; 4] = [0, 0, 0, 1];

/// The domain mask for signing commit-boost messages.
pub const COMMIT_BOOST_DOMAIN_MASK: [u8; 4] = [109, 109, 111, 67];

/// Configuration for the chain the sidecar is running on.
/// This allows to customize the slot time for custom Kurtosis devnets.
#[derive(Debug, Clone, Copy, Args, Deserialize)]
pub struct ChainConfig {
    /// Chain on which the sidecar is running
    #[clap(long, env = "BOLT_SIDECAR_CHAIN", default_value_t = Chain::Mainnet)]
    chain: Chain,
    /// The deadline in the slot at which the sidecar will stop accepting
    /// new commitments for the next block (parsed as milliseconds).
    #[clap(
        long,
        env = "BOLT_SIDECAR_COMMITMENT_DEADLINE",
        default_value_t = DEFAULT_COMMITMENT_DEADLINE_IN_MILLIS
    )]
    commitment_deadline: u64,
    /// The slot time duration in seconds. If provided,
    /// it overrides the default for the selected [Chain].
    #[clap(
        long,
        env = "BOLT_SIDECAR_SLOT_TIME",
        default_value_t = DEFAULT_SLOT_TIME_IN_SECONDS
    )]
    slot_time: u64,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain: Chain::Mainnet,
            commitment_deadline: DEFAULT_COMMITMENT_DEADLINE_IN_MILLIS,
            slot_time: DEFAULT_SLOT_TIME_IN_SECONDS,
        }
    }
}

/// Supported chains for the sidecar
#[derive(Debug, Clone, Copy, ValueEnum, Deserialize)]
#[clap(rename_all = "kebab_case")]
pub enum Chain {
    Mainnet,
    Holesky,
    Helder,
    Kurtosis,
}

impl Chain {
    /// Get the chain name for the given chain.
    pub fn name(&self) -> &'static str {
        match self {
            Chain::Mainnet => "mainnet",
            Chain::Holesky => "holesky",
            Chain::Helder => "helder",
            Chain::Kurtosis => "kurtosis",
        }
    }
}

impl Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl ChainConfig {
    /// Get the chain ID for the given chain.
    pub fn chain_id(&self) -> u64 {
        match self.chain {
            Chain::Mainnet => 1,
            Chain::Holesky => 17000,
            Chain::Helder => 7014190335,
            Chain::Kurtosis => 3151908,
        }
    }

    /// Get the chain name for the given chain.
    pub fn name(&self) -> &'static str {
        self.chain.name()
    }

    /// Get the slot time for the given chain in seconds.
    pub fn slot_time(&self) -> u64 {
        self.slot_time
    }

    /// Get the domain for signing application-builder messages on the given chain.
    pub fn application_builder_domain(&self) -> [u8; 32] {
        self.compute_domain_from_mask(APPLICATION_BUILDER_DOMAIN_MASK)
    }

    /// Get the domain for signing commit-boost messages on the given chain.
    pub fn commit_boost_domain(&self) -> [u8; 32] {
        self.compute_domain_from_mask(COMMIT_BOOST_DOMAIN_MASK)
    }

    /// Get the fork version for the given chain.
    pub fn fork_version(&self) -> [u8; 4] {
        match self.chain {
            Chain::Mainnet => [0, 0, 0, 0],
            Chain::Holesky => [1, 1, 112, 0],
            Chain::Helder => [16, 0, 0, 0],
            Chain::Kurtosis => [16, 0, 0, 56],
        }
    }

    /// Get the commitment deadline duration for the given chain.
    pub fn commitment_deadline(&self) -> Duration {
        Duration::from_millis(self.commitment_deadline)
    }

    /// Compute the domain for signing messages on the given chain.
    fn compute_domain_from_mask(&self, mask: [u8; 4]) -> [u8; 32] {
        let mut domain = [0; 32];

        let fork_version = self.fork_version();

        // Note: the application builder domain specs require the genesis_validators_root
        // to be 0x00 for any out-of-protocol message. The commit-boost domain follows the
        // same rule.
        let root = Root::default();
        let fork_data_root = compute_fork_data_root(fork_version, root).expect("valid fork data");

        domain[..4].copy_from_slice(&mask);
        domain[4..].copy_from_slice(&fork_data_root[..28]);
        domain
    }
}

#[cfg(test)]
impl ChainConfig {
    pub fn mainnet() -> Self {
        Self { chain: Chain::Mainnet, ..Default::default() }
    }

    pub fn holesky() -> Self {
        Self { chain: Chain::Holesky, ..Default::default() }
    }

    pub fn helder() -> Self {
        Self { chain: Chain::Helder, ..Default::default() }
    }

    pub fn kurtosis(slot_time_in_seconds: u64, commitment_deadline: u64) -> Self {
        Self { chain: Chain::Kurtosis, slot_time: slot_time_in_seconds, commitment_deadline }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::b256;

    const BUILDER_DOMAIN_MAINNET: [u8; 32] =
        b256!("00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9").0;

    const BUILDER_DOMAIN_HOLESKY: [u8; 32] =
        b256!("000000015b83a23759c560b2d0c64576e1dcfc34ea94c4988f3e0d9f77f05387").0;

    const BUILDER_DOMAIN_HELDER: [u8; 32] =
        b256!("0000000194c41af484fff7964969e0bdd922f82dff0f4be87a60d0664cc9d1ff").0;

    const BUILDER_DOMAIN_KURTOSIS: [u8; 32] =
        b256!("000000010b41be4cdb34d183dddca5398337626dcdcfaf1720c1202d3b95f84e").0;

    #[test]
    fn test_compute_builder_domains() {
        use super::ChainConfig;

        let mainnet = ChainConfig::mainnet();
        assert_eq!(mainnet.application_builder_domain(), BUILDER_DOMAIN_MAINNET);

        let holesky = ChainConfig::holesky();
        assert_eq!(holesky.application_builder_domain(), BUILDER_DOMAIN_HOLESKY);

        let helder = ChainConfig::helder();
        assert_eq!(helder.application_builder_domain(), BUILDER_DOMAIN_HELDER);

        let kurtosis = ChainConfig::kurtosis(0, 0);
        assert_eq!(kurtosis.application_builder_domain(), BUILDER_DOMAIN_KURTOSIS);
    }
}
