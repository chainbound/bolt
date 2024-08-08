use alloy::primitives::b256;
use clap::{Args, ValueEnum};
use std::time::Duration;

/// Default commitment deadline duration.
///
/// The sidecar will stop accepting new commitments for the next block
/// after this deadline has passed. This is to ensure that builders and
/// relays have enough time to build valid payloads.
pub const DEFAULT_COMMITMENT_DEADLINE_IN_MILLIS: u64 = 8_000;

/// Default slot time duration in seconds.
pub const DEFAULT_SLOT_TIME_IN_SECONDS: u64 = 12;

/// Builder domain for signing messages on Ethereum Mainnet.
const BUILDER_DOMAIN_MAINNET: [u8; 32] =
    b256!("00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9").0;

/// Builder domain for signing messages on Holesky.
const BUILDER_DOMAIN_HOLESKY: [u8; 32] =
    b256!("000000015b83a23759c560b2d0c64576e1dcfc34ea94c4988f3e0d9f77f05387").0;

/// Builder domain for signing messages on stock Kurtosis devnets.
const BUILDER_DOMAIN_KURTOSIS: [u8; 32] =
    b256!("000000010b41be4cdb34d183dddca5398337626dcdcfaf1720c1202d3b95f84e").0;

/// Builder domain for signing messages on Helder.
const BUILDER_DOMAIN_HELDER: [u8; 32] =
    b256!("0000000194c41af484fff7964969e0bdd922f82dff0f4be87a60d0664cc9d1ff").0;

/// Configuration for the chain the sidecar is running on.
/// This allows to customize the slot time for custom Kurtosis devnets.
#[derive(Debug, Clone, Args)]
pub struct ChainConfig {
    /// Chain on which the sidecar is running
    #[clap(long, env = "BOLT_SIDECAR_CHAIN", default_value = "mainnet")]
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
#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "kebab_case")]
#[allow(missing_docs)]
pub enum Chain {
    Mainnet,
    Holesky,
    Helder,
    Kurtosis,
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
        match self.chain {
            Chain::Mainnet => "mainnet",
            Chain::Holesky => "holesky",
            Chain::Helder => "helder",
            Chain::Kurtosis => "kurtosis",
        }
    }

    /// Get the slot time for the given chain in seconds.
    pub fn slot_time(&self) -> u64 {
        self.slot_time
    }

    /// Get the domain for signing messages on the given chain.
    pub fn builder_domain(&self) -> [u8; 32] {
        match self.chain {
            Chain::Mainnet => BUILDER_DOMAIN_MAINNET,
            Chain::Holesky => BUILDER_DOMAIN_HOLESKY,
            Chain::Helder => BUILDER_DOMAIN_HELDER,
            Chain::Kurtosis => BUILDER_DOMAIN_KURTOSIS,
        }
    }

    /// Get the fork version for the given chain.
    pub fn fork_version(&self) -> [u8; 4] {
        match self.chain {
            Chain::Mainnet => [0u8; 4],
            Chain::Holesky => [1, 1, 112, 0],
            Chain::Helder => [16, 0, 0, 0],
            Chain::Kurtosis => [16, 0, 0, 56],
        }
    }

    /// Get the commitment deadline duration for the given chain.
    pub fn commitment_deadline(&self) -> Duration {
        Duration::from_millis(self.commitment_deadline)
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
