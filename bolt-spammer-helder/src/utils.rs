use beacon_api_client::{mainnet::Client as BeaconApiClient, BlockId};
use ethers::{
    signers::Signer,
    types::{transaction::eip2718::TypedTransaction, Eip1559TransactionRequest},
    utils::hex,
};
use eyre::Result;
use rand::{thread_rng, Rng};
use serde_json::Value;

use crate::constants::{DEAD_ADDRESS, HELDER_TESTNET_CHAIN_ID, NOICE_GAS_PRICE};

/// Generates random ETH transfer to `DEAD_ADDRESS` with a random payload.
pub fn generate_random_tx() -> TypedTransaction {
    let tx = Eip1559TransactionRequest::new()
        .to(DEAD_ADDRESS)
        .value("0x69420")
        .chain_id(HELDER_TESTNET_CHAIN_ID)
        .data(vec![thread_rng().gen::<u8>(); 32]);

    let mut typed: TypedTransaction = tx.into();

    typed.set_gas_price(NOICE_GAS_PRICE);

    typed
}

/// Signs a [TypedTransaction] with the given [Signer], returning a tuple
/// with the transaction hash and the RLP-encoded signed transaction.
pub async fn sign_transaction<S: Signer>(
    signer: &S,
    tx: TypedTransaction,
) -> Result<(String, String)> {
    let Ok(signature) = signer.sign_transaction(&tx).await else {
        eyre::bail!("Failed to sign transaction")
    };

    let rlp_signed_tx = tx.rlp_signed(&signature);
    let tx_hash = format!("0x{:x}", tx.hash(&signature));
    let hex_rlp_signed_tx = format!("0x{}", hex::encode(rlp_signed_tx));

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
    let current_slot = beacon_api_client
        .get_beacon_header(BlockId::Head)
        .await?
        .header
        .message
        .slot;
    Ok(current_slot)
}
