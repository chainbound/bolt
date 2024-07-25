use std::str::FromStr;

use alloy::{
    consensus::{BlobTransactionSidecar, SidecarBuilder, SimpleCoder},
    network::TransactionBuilder,
    primitives::{Address, U256},
    rpc::types::TransactionRequest,
};
use beacon_api_client::{mainnet::Client as BeaconApiClient, BlockId, ProposerDuty};
use rand::{thread_rng, Rng};
use serde_json::Value;

pub const NOICE_GAS_PRICE: u128 = 69_420_000u128;
pub const DEAD_ADDRESS: &str = "0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD";
pub const HELDER_TESTNET_CHAIN_ID: u64 = 7014190335;

/// Generates random ETH transfer to `DEAD_ADDRESS` with a random payload.
pub fn generate_random_tx() -> TransactionRequest {
    TransactionRequest::default()
        .with_to(Address::from_str(DEAD_ADDRESS).unwrap())
        .with_chain_id(HELDER_TESTNET_CHAIN_ID)
        .with_value(U256::from(thread_rng().gen_range(1..100)))
        .with_gas_limit(1000000u128)
        .with_gas_price(NOICE_GAS_PRICE)
}

/// Generate random transaction with blob (eip4844)
pub fn generate_random_blob_tx() -> TransactionRequest {
    let sidecar: SidecarBuilder<SimpleCoder> = SidecarBuilder::from_slice(b"Blobs are fun!");
    let sidecar: BlobTransactionSidecar = sidecar.build().unwrap();

    let dead_address = Address::from_str(DEAD_ADDRESS).unwrap();

    TransactionRequest::default()
        .with_to(dead_address)
        .with_chain_id(HELDER_TESTNET_CHAIN_ID)
        .with_value(U256::from(100))
        .with_max_fee_per_blob_gas(100u128)
        .max_fee_per_gas(100u128)
        .max_priority_fee_per_gas(50u128)
        .with_gas_limit(1_000_000u128)
        .with_blob_sidecar(sidecar)
}

pub fn prepare_rpc_request(method: &str, params: Vec<Value>) -> Value {
    serde_json::json!({
        "id": "1",
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
}

/// Returns the current slot from the beacon client
pub async fn get_current_slot(beacon_api_client: &BeaconApiClient) -> eyre::Result<u64> {
    Ok(beacon_api_client.get_beacon_header(BlockId::Head).await?.header.message.slot)
}

pub async fn get_proposer_duties(
    beacon_api_client: &BeaconApiClient,
    current_slot: u64,
    current_epoch: u64,
) -> eyre::Result<Vec<ProposerDuty>> {
    Ok(beacon_api_client
        .get_proposer_duties(current_epoch)
        .await?
        .1
        .into_iter()
        .filter(|duty| duty.slot > current_slot)
        .collect::<Vec<_>>())
}
