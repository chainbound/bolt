use alloy::{
    eips::eip2718::Encodable2718,
    hex,
    network::{EthereumWallet, TransactionBuilder},
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use beacon_api_client::mainnet::Client as BeaconApiClient;
use clap::Parser;
use eyre::{bail, Result};
use tracing::info;
use url::Url;

mod registry;
use registry::BoltRegistry;

mod utils;
use utils::*;

#[derive(Parser)]
struct Opts {
    /// Bolt RPC URL to send requests to
    #[clap(short = 'p', long, default_value = "http://135.181.191.125:8015/", env)]
    rpc_url: Url,
    /// Private key to sign transactions with
    #[clap(short = 'k', long, env)]
    private_key: String,
    /// Optional nonce offset to use for the transaction
    #[clap(short, long, default_value_t = 0, env)]
    nonce_offset: u64,
    /// Flag for generating a blob tx instead of a regular tx
    #[clap(short = 'B', long, default_value_t = false)]
    blob: bool,
    /// Number of transactions to send in a sequence
    #[clap(short, long, default_value_t = 1)]
    count: u64,

    /// Flag for using the registry to fetch the lookahead
    #[clap(short, long, default_value_t = false, requires_ifs([("true", "registry_address"), ("true", "beacon_client_url")]))]
    use_registry: bool,
    /// URL of the beacon client to use for fetching the lookahead
    /// (only used with the "use-registry" flag)
    #[clap(short = 'b', long, env)]
    beacon_client_url: Option<Url>,
    /// Address of the registry contract to read bolt sidecars from
    /// (only used with the "use-registry" flag)
    #[clap(short, long, env, default_value = "0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9")]
    registry_address: Address,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("starting bolt-client");

    let _ = dotenvy::dotenv();
    let opts = Opts::parse();

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
            Ok(None) => bail!("no next preconfer slot found"),
            Err(e) => bail!("error fetching next preconfer slot from registry: {:?}", e),
        }
    } else {
        // TODO: remove "cbOnly=true"
        let url =
            opts.rpc_url.join("proposers/lookahead?onlyActive=true&onlyFuture=true&cbOnly=true")?;
        let lookahead_response = reqwest::get(url).await?.json::<serde_json::Value>().await?;
        let next_preconfer_slot = lookahead_response[0].get("slot").unwrap().as_u64().unwrap();
        (opts.rpc_url.join("/rpc")?, next_preconfer_slot)
    };

    let mut tx = if opts.blob { generate_random_blob_tx() } else { generate_random_tx() };
    tx.set_from(sender);
    tx.set_chain_id(provider.get_chain_id().await?);
    tx.set_nonce(provider.get_transaction_count(sender).await? + opts.nonce_offset);

    let tx_signed = tx.build(&transaction_signer).await?;
    let tx_hash = tx_signed.tx_hash().to_string();
    let tx_rlp = hex::encode(tx_signed.encoded_2718());

    let request = prepare_rpc_request(
        "bolt_requestInclusion",
        vec![serde_json::json!({
            "targetSlot": target_slot,
            "txs": vec![tx_rlp],
        })],
    );

    info!("Transaction hash: {}", tx_hash);

    let signature = sign_request(&tx_hash, target_slot, &wallet).await?;

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
