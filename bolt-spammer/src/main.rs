use std::{fmt, str::FromStr, sync::Arc};

use beacon_api_client::ProposerDuty;
use clap::{Parser, ValueEnum};
use config::ValidatorRange;
use ethers::{prelude::*, types::transaction::eip2718::TypedTransaction, utils::hex};
use eyre::{Context, OptionExt, Result};
use lookahead::LookaheadProvider;
use mev_share_sse::EventClient;
use rand::{thread_rng, Rng};
use serde_json::Value;
use tracing::info;

mod config;
mod events_client;
mod lookahead;

/// CLI options for the transaction spammer.
#[derive(Parser, Debug, Default)]
struct Opts {
    #[clap(short = 'k', long)]
    private_key: String,
    #[clap(short = 'n', long)]
    nonce: Option<u16>,
    #[clap(short = 'p', long)]
    protocol: Option<PreconfProtocol>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("No {protocol} proposer found in current lookahead of {lookahead_size} slots")]
    NoProposerInLookahead {
        protocol: PreconfProtocol,
        lookahead_size: usize,
    },

    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PreconfProtocol {
    Bolt,
    Titan,
}

impl fmt::Display for PreconfProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PreconfProtocol::Bolt => write!(f, "Bolt"),
            PreconfProtocol::Titan => write!(f, "Titan"),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct HeadEvent {
    slot: u64,
    block: H256,
    epoch_transition: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();
    let config = config::Config::from_toml("config.toml")?;

    let wallet = LocalWallet::from_str(&opts.private_key)?;
    let eth_provider = Arc::new(Provider::<Http>::try_from(config.execution_api)?);
    let transaction_signer = SignerMiddleware::new(eth_provider.clone(), wallet);

    let target = format!("{}/eth/v1/events?topics=head", config.beacon_api);

    let client = EventClient::default();

    let mut sub = client.subscribe::<HeadEvent>(&target).await?;

    let lookahead_provider = LookaheadProvider::new(&config.beacon_api);
    let lookahead = lookahead_provider.get_current_lookahead().await?;
    let lookahead_size = lookahead.len();
    tracing::info!(lookahead_size, "Proposer lookahead fetched");

    // Start listening to head events
    while let Some(event) = sub.next().await {
        let event = event?;
        tracing::info!(block_hash = ?event.block, "New head slot: {}", event.slot);

        if event.epoch_transition {
            let lookahead = lookahead_provider.get_current_lookahead().await?;
            tracing::info!("Epoch transition, fetched new proposer lookahead...");

            let mut tx = generate_random_tx(opts.nonce);
            tx.set_gas_price(69_420_000_000_000u128); // 69_420 gwei
            transaction_signer.fill_transaction(&mut tx, None).await?;

            let next_proposer = lookahead
                .iter()
                .find(|duty| duty.slot == event.slot + 1)
                .expect("Next proposer known");

            // Decide which protocol to use based on the CLI option. If none is provided,
            // use whatever protocol is supported by the next proposer based on the validator range.
            let (proto, endpoint, target_slot) = match opts.protocol {
                Some(PreconfProtocol::Bolt) => (
                    PreconfProtocol::Bolt,
                    config.bolt.endpoint.clone(),
                    get_next_slot_for_range(&lookahead, &config.bolt.validator_range).ok_or(
                        Error::NoProposerInLookahead {
                            protocol: PreconfProtocol::Bolt,
                            lookahead_size,
                        },
                    )?,
                ),
                Some(PreconfProtocol::Titan) => (
                    PreconfProtocol::Titan,
                    config.titan.endpoint.clone(),
                    get_next_slot_for_range(&lookahead, &config.titan.validator_range).ok_or(
                        Error::NoProposerInLookahead {
                            protocol: PreconfProtocol::Titan,
                            lookahead_size,
                        },
                    )?,
                ),
                None => {
                    if config
                        .bolt
                        .validator_range
                        .is_in_range(next_proposer.validator_index)
                    {
                        (
                            PreconfProtocol::Bolt,
                            config.bolt.endpoint.clone(),
                            next_proposer.slot,
                        )
                    } else {
                        (
                            PreconfProtocol::Titan,
                            config.titan.endpoint.clone(),
                            next_proposer.slot,
                        )
                    }
                }
            };

            tracing::info!(
                slot = target_slot,
                supported_protocol = ?proto,
                "Next proposer found"
            );

            let (tx_hash, tx_rlp) = sign_transaction(transaction_signer.signer(), tx).await?;

            let message_digest = {
                let mut data = Vec::new();
                data.extend_from_slice(&target_slot.to_le_bytes());
                data.extend_from_slice(hex::decode(tx_hash.trim_start_matches("0x"))?.as_slice());
                H256::from(ethers::utils::keccak256(data))
            };

            let signature = transaction_signer
                .signer()
                .sign_hash(message_digest)?
                .to_string();

            let request = prepare_rpc_request(
                "bolt_inclusionPreconfirmation",
                vec![serde_json::json!({
                    "slot": target_slot,
                    "tx": tx_rlp,
                    "signature": signature,
                })],
            );

            info!("Transaction hash: {}", tx_hash);
            info!("body: {}", serde_json::to_string(&request)?);

            let response = send_preconf_to(&endpoint, request).await?;
            info!("Response: {:?}", response.text().await?);
        }
    }

    Ok(())
}

fn get_next_slot_for_range(lookahead: &[ProposerDuty], range: &ValidatorRange) -> Option<u64> {
    for duty in lookahead {
        if range.is_in_range(duty.validator_index) {
            return Some(duty.slot);
        }
    }

    None
}

async fn send_preconf_to(endpoint: &str, request: Value) -> Result<reqwest::Response, Error> {
    let client = reqwest::Client::new();
    let response = client
        .post(endpoint)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request)?)
        .send()
        .await?;

    Ok(response)
}

fn generate_random_tx(nonce: Option<u16>) -> TypedTransaction {
    let mut tx = Eip1559TransactionRequest::new()
        .to("0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD")
        .value("0x69420")
        .chain_id(3151908)
        .data(vec![thread_rng().gen::<u8>(); 32]);

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
