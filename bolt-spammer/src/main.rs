use std::{str::FromStr, sync::Arc};

use clap::Parser;
use ethers::{prelude::*, types::transaction::eip2718::TypedTransaction, utils::hex};
use eyre::{Context, OptionExt, Result};
use serde_json::Value;
use tracing::info;

#[derive(Parser)]
struct Opts {
    #[clap(short = 'p', long, default_value = "http://localhost:8545")]
    provider_url: String,
    #[clap(short = 'c', long, default_value = "http://localhost:4000")]
    beacon_client_url: String,
    #[clap(short = 'b', long)]
    bolt_sidecar_url: String,
    #[clap(short = 'k', long)]
    private_key: String,
    #[clap(short = 'n', long)]
    nonce: Option<u16>,
    #[clap(short = 's', long, default_value = "head")]
    slot: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    let wallet = LocalWallet::from_str(&opts.private_key)?;
    let eth_provider = Arc::new(Provider::<Http>::try_from(opts.provider_url)?);
    let transaction_signer = SignerMiddleware::new(eth_provider.clone(), wallet);

    let mut tx = generate_random_tx(opts.nonce);
    tx.set_gas_price(1_000_000_000_000u128); // 1000 gwei
    transaction_signer.fill_transaction(&mut tx, None).await?;

    let slot_number = match opts.slot.parse::<u64>() {
        Ok(num) => num,
        Err(_) => {
            // Attempt to fetch slot number from the beacon API.
            // This works with notable slots: "head", "genesis", "finalized"
            get_slot(&opts.beacon_client_url, &opts.slot).await? + 3
        }
    };

    let (tx_hash, tx_rlp) = sign_transaction(transaction_signer.signer(), tx).await?;
    let request = prepare_rpc_request(
        "eth_requestPreconfirmation",
        vec![serde_json::json!({
            "txHash": tx_hash,
            "rawTx": tx_rlp,
            "slot": slot_number,
        })],
    );

    info!("Transaction hash: {}", tx_hash);
    info!("body: {}", serde_json::to_string(&request)?);

    let client = reqwest::Client::new();
    let response = client
        .post(&opts.bolt_sidecar_url)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request)?)
        .send()
        .await?;

    info!("Response: {:?}", response.text().await?);

    Ok(())
}

fn generate_random_tx(nonce: Option<u16>) -> TypedTransaction {
    let mut tx = Eip1559TransactionRequest::new()
        .to("0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD")
        .value("0x69420")
        .chain_id(3151908);

    tx = if let Some(nonce) = nonce {
        tx.nonce(nonce)
    } else {
        // `fill_transaction` can automatically set the nonce if it's not provided
        tx
    };

    tx.into()
}

/// Signs a [TypedTransaction] with the given [Signer], returning a tuple
/// with the transaction hash and the RLP-encoded signed transaction.
async fn sign_transaction<S: Signer>(signer: &S, tx: TypedTransaction) -> Result<(String, String)> {
    let Ok(signature) = signer.sign_transaction(&tx).await else {
        eyre::bail!("Failed to sign transaction")
    };

    let rlp_signed_tx = tx.rlp_signed(&signature);
    let tx_hash = format!("0x{:x}", tx.hash(&signature));
    let hex_rlp_signed_tx = format!("0x{}", hex::encode(rlp_signed_tx));

    Ok((tx_hash, hex_rlp_signed_tx))
}

fn prepare_rpc_request(method: &str, params: Vec<Value>) -> Value {
    serde_json::json!({
        "id": "1",
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
}

async fn get_slot(beacon_url: &str, slot: &str) -> Result<u64> {
    let url = format!("{}/eth/v1/beacon/headers/{}", beacon_url, slot);

    let res = reqwest::get(url).await?;
    let json: Value = serde_json::from_str(&res.text().await?)?;

    let slot_num = json
        .pointer("/data/header/message/slot")
        .ok_or_eyre("slot not found")?
        .as_str()
        .ok_or_eyre("slot is not a string")?
        .parse::<u64>()
        .wrap_err("failed to parse slot")?;

    Ok(slot_num)
}
