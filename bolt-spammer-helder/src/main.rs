use std::{path::PathBuf, str::FromStr};

use alloy::{
    hex,
    network::EthereumWallet,
    signers::{local::PrivateKeySigner, Signer},
};
use beacon_api_client::mainnet::Client as BeaconApiClient;
use bolt_spammer_helder::{
    constants::SLOTS_PER_EPOCH,
    contract::BoltRegistry,
    utils::{
        current_slot, generate_random_blob_tx, generate_random_tx, prepare_rpc_request,
        sign_transaction,
    },
};
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use reth_primitives::Address;
use tracing::info;

#[derive(Parser)]
struct Opts {
    #[clap(short = 'p', long, default_value = "https://rpc.helder-devnets.xyz", env)]
    el_provider_url: String,
    #[clap(short = 'c', long, default_value = "http://localhost:4000", env)]
    beacon_client_url: Url,
    #[clap(short = 'r', long, default_value = "0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9", env)]
    registry_address: Address,
    #[clap(short = 'k', long, env)]
    private_key: String,
    #[clap(short = 'a', long, env, default_value = "./registry_abi.json")]
    registry_abi_path: PathBuf,
    // Flag for generating a blob tx instead of a regular tx
    #[clap(short, long, default_value = "false")]
    blob: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("starting bolt-spammer-helder");

    let path = dotenvy::dotenv()?;
    tracing::info!("loaded environment variables from {:?}", path);
    let opts = Opts::parse();

    let wallet: PrivateKeySigner = opts.private_key.parse().expect("should parse private key");
    let transaction_signer: EthereumWallet = wallet.clone().into();

    let beacon_api_client = BeaconApiClient::new(opts.beacon_client_url);

    let registry = BoltRegistry::new(Url::from_str(&opts.el_provider_url)?, opts.registry_address);

    let current_slot = current_slot(&beacon_api_client).await?;

    tracing::info!(
        "current slot is {}, end of epoch in {} slots",
        current_slot,
        SLOTS_PER_EPOCH - (current_slot % SLOTS_PER_EPOCH)
    );

    let current_epoch = current_slot / SLOTS_PER_EPOCH;
    let proposer_duties = beacon_api_client
        .get_proposer_duties(current_epoch)
        .await?
        .1
        .into_iter()
        .filter(|duty| duty.slot > current_slot)
        .collect::<Vec<_>>();

    let (proposer_rpc, next_preconfer_slot) =
        match registry.next_preconfer_from_registry(proposer_duties).await {
            Ok(Some(res)) => res,
            Ok(None) => {
                tracing::info!("no next preconfer slot found");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(?e);
                return Ok(());
            }
        };

    let tx = if opts.blob { generate_random_blob_tx() } else { generate_random_tx() };

    let (tx_hash, tx_rlp) = sign_transaction(&transaction_signer, tx).await?;

    let message_digest = {
        let mut data = Vec::new();
        data.extend_from_slice(&next_preconfer_slot.to_le_bytes());
        data.extend_from_slice(hex::decode(tx_hash.trim_start_matches("0x"))?.as_slice());
        data
    };

    let signature = wallet.sign_message(message_digest.as_ref()).await?;

    let request = prepare_rpc_request(
        "bolt_inclusionPreconfirmation",
        vec![serde_json::json!({
            "slot": next_preconfer_slot,
            "tx": tx_rlp,
            "signature": signature,
        })],
    );

    info!("Transaction hash: {}", tx_hash);
    info!("body: {}", serde_json::to_string(&request)?);

    let client = reqwest::Client::new();
    let response = client
        .post(proposer_rpc)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request)?)
        .send()
        .await?;

    info!("Response: {:?}", response.text().await?);

    Ok(())
}
