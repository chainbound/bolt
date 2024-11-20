use std::collections::HashMap;

use alloy::primitives::{address, Address};

use crate::cli::Chain;

pub mod eigenlayer;
pub mod erc20;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum BoltContract {
    Validators,
}

// PERF: this should be done at compile time
pub fn deployments() -> HashMap<Chain, HashMap<BoltContract, Address>> {
    let mut deployments = HashMap::new();
    let mut holesky_deployments = HashMap::new();
    holesky_deployments
        .insert(BoltContract::Validators, address!("47D2DC1DE1eFEFA5e6944402f2eda3981D36a9c8"));
    deployments.insert(Chain::Holesky, holesky_deployments);

    deployments
}

pub fn bolt_validators_address(chain: Chain) -> Address {
    *deployments()
        .get(&chain)
        .unwrap_or_else(|| panic!("{:?} chain supported", chain))
        .get(&BoltContract::Validators)
        .expect("Validators contract address not found")
}
