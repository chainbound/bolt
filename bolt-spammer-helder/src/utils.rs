use std::str::FromStr;

use alloy::{
    consensus::{BlobTransactionSidecar, SidecarBuilder, SimpleCoder},
    hex,
    network::{eip2718::Encodable2718, EthereumWallet, TransactionBuilder},
    primitives::{Address, U256},
    rpc::types::TransactionRequest,
};
use beacon_api_client::{mainnet::Client as BeaconApiClient, BlockId};
use eyre::Result;
use rand::{thread_rng, Rng};
use reth_primitives::TransactionSigned;
use serde_json::Value;

use crate::constants::{DEAD_ADDRESS, HELDER_TESTNET_CHAIN_ID, NOICE_GAS_PRICE};

/// Generates random ETH transfer to `DEAD_ADDRESS` with a random payload.
pub fn generate_random_tx() -> TransactionRequest {
    TransactionRequest::default()
        .with_to(Address::from_str(DEAD_ADDRESS).unwrap())
        .with_chain_id(HELDER_TESTNET_CHAIN_ID)
        .with_value(U256::from(thread_rng().gen_range(1..100)))
        .with_gas_price(NOICE_GAS_PRICE)
}

/// Generate random transaction with blob (eip4844)
pub fn generate_random_blob_tx() -> TransactionRequest {
    let sidecar: SidecarBuilder<SimpleCoder> = SidecarBuilder::from_slice(b"Blobs are fun!");
    let sidecar: BlobTransactionSidecar = sidecar.build().unwrap();

    let dead_address = Address::from_str(DEAD_ADDRESS).unwrap();

    let tx: TransactionRequest = TransactionRequest::default()
        .with_to(dead_address)
        .with_chain_id(HELDER_TESTNET_CHAIN_ID)
        .with_value(U256::from(100))
        .with_gas_price(NOICE_GAS_PRICE)
        .with_blob_sidecar(sidecar);

    tx
}

/// Signs a [TypedTransaction] with the given [Signer], returning a tuple
/// with the transaction hash and the RLP-encoded signed transaction.
pub async fn sign_transaction(
    signer: &EthereumWallet,
    tx: TransactionRequest,
) -> Result<(String, String)> {
    let Ok(signed) = tx.build(signer).await else {
        return Err(eyre::eyre!("Failed to sign transaction"));
    };
    let tx_signed_bytes = signed.encoded_2718();
    let tx_signed = TransactionSigned::decode_enveloped(&mut tx_signed_bytes.as_slice()).unwrap();

    let tx_hash = tx_signed.hash().to_string();
    let hex_rlp_signed_tx = format!("0x{}", hex::encode(tx_signed_bytes));

    Ok((tx_hash, hex_rlp_signed_tx))
}

pub fn prepare_rpc_request(method: &str, params: Vec<Value>) -> Value {
    serde_json::json!({
        "id": "1",
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
}

/// Returns the current slot
pub async fn current_slot(beacon_api_client: &BeaconApiClient) -> Result<u64> {
    let current_slot =
        beacon_api_client.get_beacon_header(BlockId::Head).await?.header.message.slot;
    Ok(current_slot)
}
