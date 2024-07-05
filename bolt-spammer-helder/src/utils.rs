use beacon_api_client::{mainnet::Client as BeaconApiClient, BlockId};
use ethers::{
    abi::Token,
    signers::Signer,
    types::{transaction::eip2718::TypedTransaction, Eip1559TransactionRequest},
    utils::hex,
};
use eyre::{eyre, Result};
use rand::{thread_rng, Rng};
use serde_json::Value;

/// Tries to parse the registered validator's sidecars URL from the token returned
/// by the view call to the registry smart contract
///
/// Reference: https://github.com/chainbound/bolt/blob/e71c61aa97dcd7b08fad23067caf18bc90a582cd/bolt-contracts/src/interfaces/IBoltRegistry.sol#L6-L16
pub fn try_parse_url_from_token(token: Token) -> Result<String> {
    let Token::Tuple(registrant_struct_fields) = token else {
        return Err(eyre!("register call result is not a struct"));
    };

    let Some(metadata_token) = registrant_struct_fields.last() else {
        return Err(eyre!("register call result is a struct with no fields"));
    };

    let Token::Tuple(metadata_fields) = metadata_token else {
        return Err(eyre!(
            "register call result is a struct without the `metadata` field"
        ));
    };

    let Some(rpc_token) = metadata_fields.first() else {
        return Err(eyre!(
            "register call result has a `metadata` field, but the struct is empty"
        ));
    };

    let Token::String(rpc) = rpc_token else {
        return Err(eyre!(
            "register call result has a `metadata` field, but its `rpc` property is not a string"
        ));
    };

    Ok(rpc.clone())
}

/// Generates random ETH transfer to 0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD
pub fn generate_random_tx() -> TypedTransaction {
    let tx = Eip1559TransactionRequest::new()
        .to("0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD")
        .value("0x69420")
        .chain_id(3151908)
        .data(vec![thread_rng().gen::<u8>(); 32]);

    tx.into()
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

pub async fn current_epoch(beacon_api_client: &BeaconApiClient) -> Result<u64> {
    let current_epoch = beacon_api_client
        .get_beacon_header(BlockId::Head)
        .await?
        .header
        .message
        .slot
        / 32;

    Ok(current_epoch)
}
