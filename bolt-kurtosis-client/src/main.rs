use alloy::{
    eips::eip2718::Encodable2718,
    hex,
    network::{EthereumWallet, TransactionBuilder},
    primitives::keccak256,
    providers::{Provider, ProviderBuilder},
    signers::{local::PrivateKeySigner, Signer},
};
use beacon_api_client::mainnet::Client as BeaconApiClient;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use tracing::info;

pub mod constants;
pub mod utils;

use utils::{current_slot, generate_random_blob_tx, generate_random_tx, prepare_rpc_request};

#[derive(Parser)]
struct Opts {
    #[clap(short = 'p', long, default_value = "http://localhost:8545")]
    provider_url: Url,
    #[clap(short = 'c', long, default_value = "http://localhost:4000")]
    beacon_client_url: Url,
    #[clap(short = 'b', long)]
    bolt_sidecar_url: String,
    #[clap(short = 'k', long)]
    private_key: String,
    #[clap(short = 'n', long)]
    nonce: Option<u16>,
    #[clap(short = 'B', long, default_value_t = false)]
    blob: bool,
    #[clap(short = 's', long, default_value = "head")]
    slot: String,
    #[clap(short = 'C', long, default_value_t = 1)]
    count: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("starting bolt-spammer");

    let opts = Opts::parse();

    let wallet: PrivateKeySigner = opts.private_key.parse().expect("should parse private key");

    let sender = wallet.address();
    let transaction_signer: EthereumWallet = wallet.clone().into();
    let provider = ProviderBuilder::new().on_http(opts.provider_url);

    let beacon_api_client = BeaconApiClient::new(opts.beacon_client_url);

    let current_slot = current_slot(&beacon_api_client).await?;
    let target_slot = if opts.slot == "head" { current_slot + 2 } else { opts.slot.parse()? };

    for i in 0..opts.count {
        let mut tx = if opts.blob { generate_random_blob_tx() } else { generate_random_tx() };
        tx.set_from(sender);
        tx.set_nonce(provider.get_transaction_count(sender).await? + i);

        let tx_signed = tx.build(&transaction_signer).await?;
        let tx_hash = tx_signed.tx_hash().to_string();
        let tx_rlp = hex::encode(tx_signed.encoded_2718());

        let message_digest = {
            let mut data = Vec::new();
            data.extend_from_slice(&target_slot.to_le_bytes());
            data.extend_from_slice(hex::decode(tx_hash.trim_start_matches("0x"))?.as_slice());
            keccak256(data)
        };

        let signature = wallet.sign_hash(&message_digest).await?;
        let signature = hex::encode(signature.as_bytes());
        let signature_header = format!("{}:0x{}", wallet.address(), &signature);

        let request = prepare_rpc_request(
            "bolt_requestInclusion",
            vec![serde_json::json!({
                "targetSlot": target_slot,
                "txs": vec![tx_rlp],
            })],
        );

        info!("Transaction hash: {}", tx_hash);
        info!("body: {}", serde_json::to_string(&request)?);

        let client = reqwest::Client::new();
        let response = client
            .post(&opts.bolt_sidecar_url)
            .header("content-type", "application/json")
            .header("x-bolt-signature", signature_header)
            .body(serde_json::to_string(&request)?)
            .send()
            .await?;

        info!("Response: {:?}", response.text().await?);
    }

    Ok(())
}
