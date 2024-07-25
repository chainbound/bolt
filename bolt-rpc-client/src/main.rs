use alloy::{
    eips::eip2718::Encodable2718,
    hex,
    network::{EthereumWallet, TransactionBuilder},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use tracing::info;
use url::Url;
use utils::{generate_random_blob_tx, generate_random_tx, prepare_rpc_request};

mod utils;

#[derive(Parser)]
struct Opts {
    /// Bolt RPC URL to send requests to
    #[clap(short = 'p', long, default_value = "http://135.181.191.125:8015/", env)]
    rpc_url: Url,
    /// Private key to sign transactions with
    #[clap(short = 'k', long, env)]
    private_key: String,
    /// Optional nonce offset to use for the transaction
    #[clap(short, long, default_value = "0")]
    nonce_offset: u64,
    // Flag for generating a blob tx instead of a regular tx
    #[clap(short, long, default_value = "false")]
    blob: bool,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("starting bolt-rpc-client");

    let _ = dotenvy::dotenv();
    let opts = Opts::parse();

    let wallet: PrivateKeySigner = opts.private_key.parse().expect("should parse private key");
    let transaction_signer: EthereumWallet = wallet.clone().into();
    let provider = ProviderBuilder::new().on_http(opts.rpc_url.clone());
    let sender = wallet.address();

    let mut tx = if opts.blob { generate_random_blob_tx() } else { generate_random_tx() };
    tx.set_from(sender);
    tx.set_nonce(provider.get_transaction_count(sender).await? + opts.nonce_offset);

    let tx_signed = tx.build(&transaction_signer).await?;
    let tx_hash = tx_signed.tx_hash().to_string();
    let tx_rlp = hex::encode(tx_signed.encoded_2718());

    // TODO: remove "cbOnly=true"
    let url = opts.rpc_url.join("proposers/lookahead?onlyActive=true&onlyFuture=true&cbOnly=true")?;
    let lookahead_response = reqwest::get(url).await?.json::<serde_json::Value>().await?;
    let next_preconfer_slot = lookahead_response[0].get("slot").unwrap().as_u64().unwrap();

    let request = prepare_rpc_request(
        "bolt_requestInclusion",
        vec![serde_json::json!({
            "slot": next_preconfer_slot,
            "tx": tx_rlp,
        })],
    );

    info!("Transaction hash: {}", tx_hash);

    let response = reqwest::Client::new()
        .post(opts.rpc_url.join("/rpc")?)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request)?)
        .send()
        .await?;

    let response = response.text().await?;

    // strip out long series of zeros in the response (to avoid spamming blob contents)
    let response = response.replace(&"0".repeat(32), ".").replace(&".".repeat(4), "");
    info!("Response: {:?}", response);

    Ok(())
}
