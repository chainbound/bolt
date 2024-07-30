use alloy::{
    eips::eip2718::Encodable2718,
    hex,
    network::{EthereumWallet, TransactionBuilder},
    primitives::{address, Address, B256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use beacon_api_client::mainnet::Client as BeaconApiClient;
use clap::Parser;
use eyre::{bail, Result};
use serde_json::{json, Value};
use tracing::info;
use url::Url;

mod registry;
use registry::BoltRegistry;

mod utils;
use utils::*;

// Default Bolt RPC URL (on Helder)
pub const DEFAULT_RPC_URL: &str = "https://bolt.chainbound.io/rpc";

// Default Bolt-Registry address (on Helder)
pub const DEFAULT_REGISTRY: Address = address!("dF11D829eeC4C192774F3Ec171D822f6Cb4C14d9");

#[derive(Parser)]
struct Opts {
    /// Bolt RPC URL to send requests to
    #[clap(long, default_value = DEFAULT_RPC_URL, env = "BOLT_RPC_URL")]
    rpc_url: Url,
    /// Private key to sign transactions with
    #[clap(short = 'k', long, env = "BOLT_PRIVATE_KEY")]
    private_key: String,
    /// Optional nonce offset to use for the transaction
    #[clap(long, default_value_t = 0, env = "BOLT_NONCE_OFFSET")]
    nonce_offset: u64,
    /// Flag for generating a blob tx instead of a regular tx
    #[clap(long, default_value_t = false)]
    blob: bool,
    /// Number of transactions to send in a sequence
    #[clap(long, default_value_t = 1)]
    count: u64,
    /// Flag for sending all "count" transactions in a single bundle
    #[clap(long, default_value_t = false)]
    bundle: bool,

    /// Flag for using the registry to fetch the lookahead
    #[clap(long, default_value_t = false, requires_ifs([("true", "registry_address"), ("true", "beacon_client_url")]))]
    use_registry: bool,
    /// URL of the beacon client to use for fetching the lookahead
    /// (only used with the "use-registry" flag)
    #[clap(short = 'b', long, env = "BOLT_BEACON_CLIENT_URL")]
    beacon_client_url: Option<Url>,
    /// Address of the registry contract to read bolt sidecars from
    /// (only used with the "use-registry" flag)
    #[clap(long, env = "BOLT_REGISTRY_ADDRESS", default_value_t = DEFAULT_REGISTRY)]
    registry_address: Address,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("starting bolt-client");

    let _ = dotenvy::dotenv();
    let mut opts = Opts::parse();

    let wallet: PrivateKeySigner = opts.private_key.parse().expect("invalid private key");
    let transaction_signer: EthereumWallet = wallet.clone().into();
    let provider = ProviderBuilder::new().on_http(opts.rpc_url.clone());
    let sender = wallet.address();

    let (target_sidecar_url, target_slot) = if opts.use_registry {
        // Fetch the next preconfer slot from the registry and use it
        let beacon_api_client = BeaconApiClient::new(opts.beacon_client_url.unwrap());
        let registry = BoltRegistry::new(opts.rpc_url, opts.registry_address);
        let curr_slot = get_current_slot(&beacon_api_client).await?;
        let duties = get_proposer_duties(&beacon_api_client, curr_slot, curr_slot / 32).await?;
        match registry.next_preconfer_from_registry(duties).await {
            Ok(Some((endpoint, slot))) => (Url::parse(&endpoint)?, slot),
            Ok(None) => bail!("no next preconfer slot found, try again later"),
            Err(e) => bail!("error fetching next preconfer slot from registry: {:?}", e),
        }
    } else {
        let url = opts.rpc_url.join("proposers/lookahead?activeOnly=true&futureOnly=true")?;
        let lookahead_response = reqwest::get(url).await?.json::<Value>().await?;
        if lookahead_response.as_array().unwrap_or(&vec![]).is_empty() {
            bail!("no bolt proposer found in lookahead, try again later 🥲");
        }
        let next_preconfer_slot = lookahead_response[0].get("slot").unwrap().as_u64().unwrap();
        (opts.rpc_url, next_preconfer_slot)
    };

    let mut txs_rlp = Vec::with_capacity(opts.count as usize);
    let mut tx_hashes = Vec::with_capacity(opts.count as usize);
    for _ in 0..opts.count {
        let mut tx = if opts.blob { generate_random_blob_tx() } else { generate_random_tx() };
        tx.set_from(sender);
        tx.set_chain_id(provider.get_chain_id().await?);
        tx.set_nonce(provider.get_transaction_count(sender).await? + opts.nonce_offset);

        // Set the nonce offset for the next transaction
        opts.nonce_offset += 1;

        let tx_signed = tx.build(&transaction_signer).await?;
        let tx_hash = tx_signed.tx_hash();
        let tx_rlp = hex::encode(tx_signed.encoded_2718());

        if opts.bundle {
            // store transactions in a bundle to send them all at once
            txs_rlp.push(tx_rlp);
            tx_hashes.push(*tx_hash);
        } else {
            // Send rpc requests singularly for each transaction
            send_rpc_request(
                vec![tx_rlp],
                vec![*tx_hash],
                target_slot,
                target_sidecar_url.clone(),
                &wallet,
            )
            .await?;
        }
    }

    if opts.bundle {
        send_rpc_request(txs_rlp, tx_hashes, target_slot, target_sidecar_url, &wallet).await?;
    }

    Ok(())
}

async fn send_rpc_request(
    txs_rlp: Vec<String>,
    tx_hashes: Vec<B256>,
    target_slot: u64,
    target_sidecar_url: Url,
    wallet: &PrivateKeySigner,
) -> Result<()> {
    let request = prepare_rpc_request(
        "bolt_requestInclusion",
        json!({
            "slot": target_slot,
            "txs": txs_rlp,
        }),
    );

    info!(?tx_hashes, target_slot, %target_sidecar_url);
    let signature = sign_request(tx_hashes, target_slot, wallet).await?;

    let response = reqwest::Client::new()
        .post(target_sidecar_url)
        .header("content-type", "application/json")
        .header("x-bolt-signature", signature)
        .body(serde_json::to_string(&request)?)
        .send()
        .await?;

    let response = response.text().await?;

    // strip out long series of zeros in the response (to avoid spamming blob contents)
    let response = response.replace(&"0".repeat(32), ".").replace(&".".repeat(4), "");
    info!("Response: {:?}", response);
    Ok(())
}
