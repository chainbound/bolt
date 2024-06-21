use std::{
    collections::HashMap,
    fmt,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use beacon_api_client::ProposerDuty;
use clap::{Parser, ValueEnum};
use colored::*;
use config::ValidatorRange;
use ethers::{prelude::*, types::transaction::eip2718::TypedTransaction, utils::hex};
use events_client::{
    EventsClient, PreconfRequestedEvent, PreconfRespondedEvent, PreconfsConfirmedEvent,
};
use eyre::{Context, OptionExt, Result};
use lookahead::LookaheadProvider;
use mev_share_sse::EventClient;
use rand::{thread_rng, Rng};
use serde_json::Value;
use tracing::{debug, info};

mod config;
mod events_client;
mod lookahead;

const ASCII: &str = r#" ______     ____            _ _
|___  /    |  _ \          | (_)
   / /_   _| |_) | ___ _ __| |_ _ __
  / /| | | |  _ < / _ \ '__| | | '_ \
 / /_| |_| | |_) |  __/ |  | | | | | |
/_____\__,_|____/ \___|_|  |_|_|_| |_|
 _____                           __ _                      _   _
|  __ \                         / _(_)                    | | (_)
| |__) | __ ___  ___ ___  _ __ | |_ _ _ __ _ __ ___   __ _| |_ _  ___  _ __  ___
|  ___/ '__/ _ \/ __/ _ \| '_ \|  _| | '__| '_ ` _ \ / _` | __| |/ _ \| '_ \/ __|
| |   | | |  __/ (_| (_) | | | | | | | |  | | | | | | (_| | |_| | (_) | | | \__ \
|_|   |_|  \___|\___\___/|_| |_|_| |_|_|  |_| |_| |_|\__,_|\__|_|\___/|_| |_|___/
 _____                        _
|  __ \                      | |
| |  | | _____   ___ __   ___| |_
| |  | |/ _ \ \ / / '_ \ / _ \ __|
| |__| |  __/\ V /| | | |  __/ |_
|_____/ \___| \_/ |_| |_|\___|\__|

   __         __
  /.-'       `-.\
 //             \\
/j_______________j\
/o.-==-. .-. .-==-.o\
||      )) ((      ||
\\____//   \\____//
 `-==-'     `-==-'
"#;

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

    #[error("Request failed with code: {0}")]
    RequestFailed(u16),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PreconfProtocol {
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
    #[serde(deserialize_with = "string_to_u64")]
    slot: u64,
    block: H256,
    epoch_transition: bool,
}

fn string_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();
    let config = config::Config::from_toml("config.toml")?;

    let eth_provider = Arc::new(Provider::<Http>::try_from(config.execution_api)?);

    let signers = vec![
        SignerMiddleware::new(
            eth_provider.clone(),
            LocalWallet::from_str(
                "bb1d0f125b4fb2bb173c318cdead45468474ca71474e2247776b2b4c0fa2d3f5",
            )?,
        ),
        SignerMiddleware::new(
            eth_provider.clone(),
            LocalWallet::from_str(
                "850643a0224065ecce3882673c21f56bcf6eef86274cc21cadff15930b59fc8c",
            )?,
        ),
        SignerMiddleware::new(
            eth_provider.clone(),
            LocalWallet::from_str(
                "94eb3102993b41ec55c241060f47daa0f6372e2e3ad7e91612ae36c364042e44",
            )?,
        ),
        SignerMiddleware::new(
            eth_provider.clone(),
            LocalWallet::from_str(
                "daf15504c22a352648a71ef2926334fe040ac1d5005019e09f6c979808024dc7",
            )?,
        ),
        SignerMiddleware::new(
            eth_provider.clone(),
            LocalWallet::from_str(
                "eaba42282ad33c8ef2524f07277c03a776d98ae19f581990ce75becb7cfa1c23",
            )?,
        ),
        SignerMiddleware::new(
            eth_provider.clone(),
            LocalWallet::from_str(
                "3fd98b5187bf6526734efaa644ffbb4e3670d66f5d0268ce0323ec09124bff61",
            )?,
        ),
        SignerMiddleware::new(
            eth_provider.clone(),
            LocalWallet::from_str(
                "5288e2f440c7f0cb61a9be8afdeb4295f786383f96f5e35eb0c94ef103996b64",
            )?,
        ),
        SignerMiddleware::new(
            eth_provider.clone(),
            LocalWallet::from_str(
                "f296c7802555da2a5a662be70e078cbd38b44f96f8615ae529da41122ce8db05",
            )?,
        ),
    ];

    println!("{ASCII}");

    let events_client = config
        .events_api
        .map(EventsClient::new)
        .ok_or_else(|| eyre::eyre!("Events API not configured"))?;

    let mut preconf_cache: HashMap<u64, Vec<String>> = HashMap::new();

    let target = format!("{}/eth/v1/events?topics=head", config.beacon_api);

    let client = EventClient::default();

    let mut sub = client.subscribe::<HeadEvent>(&target).await?;

    let lookahead_provider = LookaheadProvider::new(&config.beacon_api);
    let mut lookahead = lookahead_provider.get_current_lookahead().await?;
    let lookahead_size = lookahead.len();
    tracing::info!(lookahead_size, "Proposer lookahead fetched");

    // Start listening to head events
    let mut signer_idx = 0;
    while let Some(event) = sub.next().await {
        println!();
        let event = event?;
        tracing::info!(block_hash = ?event.block, "New head slot: {}", event.slot);
        tracing::info!("-----------------------------------------------------------------------------------------------");

        tokio::time::sleep(Duration::from_millis(500)).await;

        if event.epoch_transition {
            lookahead = lookahead_provider.get_current_lookahead().await?;
            tracing::info!("Epoch transition, fetched new proposer lookahead...");
        }

        let Some(next_proposer) = lookahead.iter().find(|duty| duty.slot == event.slot + 1) else {
            tracing::warn!("At end of epoch, waiting");

            // Sending an empty event to make the frontend advance
            if let Err(e) = events_client
                .preconf_requested(PreconfRequestedEvent {
                    protocol_id: "Unknown".to_string(),
                    tx_hash: "0x6a07b1ef329f98d258c0a0bfe4232d63dbecb452174adafd380e8098890d0d8f"
                        .to_string(),
                    timestamp: unix_millis(),
                    slot: event.slot,
                    validator_index: 89,
                    endpoint: "http://localhost:8080".to_string(),
                })
                .await
            {
                tracing::error!(error = ?e, "Failed publishing preconf requested event");
            }

            continue;
        };

        // Decide which protocol to use based on the CLI option. If none is provided,
        // use whatever protocol is supported by the next proposer based on the validator range.
        let mut is_vanilla = false;
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
                } else if config
                    .titan
                    .validator_range
                    .is_in_range(next_proposer.validator_index)
                {
                    (
                        PreconfProtocol::Titan,
                        config.titan.endpoint.clone(),
                        next_proposer.slot,
                    )
                } else {
                    // Next proposer is vanilla
                    tracing::warn!(slot = next_proposer.slot, index = next_proposer.validator_index, "Proposer for next slot is vanilla proposer, looking for next preconf proposer...");
                    is_vanilla = true;
                    let mut proto = None;
                    let next_supported = lookahead
                        .iter()
                        .skip_while(|duty| duty.slot <= event.slot + 1)
                        .find(|duty| {
                            if config
                                .bolt
                                .validator_range
                                .is_in_range(duty.validator_index)
                            {
                                proto = Some((PreconfProtocol::Bolt, config.bolt.endpoint.clone()));
                                true
                            } else if config
                                .titan
                                .validator_range
                                .is_in_range(duty.validator_index)
                            {
                                proto =
                                    Some((PreconfProtocol::Titan, config.titan.endpoint.clone()));
                                true
                            } else {
                                false
                            }
                        });

                    if let Some(proposer) = next_supported {
                        tracing::info!(
                            validator_index = proposer.validator_index,
                            "Found next supported proposer at slot {}",
                            proposer.slot
                        );

                        let (protocol, endpoint) = proto.unwrap();

                        (protocol, endpoint, proposer.slot)
                    } else {
                        tracing::warn!(
                            slot = next_proposer.slot,
                            "No preconf proposer found in lookahead, skipping..."
                        );

                        // still send something for the demo to advance
                        (
                            PreconfProtocol::Titan,
                            config.titan.endpoint.clone(),
                            next_proposer.slot,
                        )
                    }
                }
            }
        };

        tracing::info!(
            slot = target_slot,
            validator_index = next_proposer.validator_index,
            supported_protocol = ?proto,
            "Next preconf proposer found"
        );

        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(200)).await;

            // pick a signer in round robin fashion to avoid nonce conflicts
            let transaction_signer = &signers[signer_idx];
            signer_idx = (signer_idx + 1) % signers.len();

            // create a random transaction with a high gas price and sign it
            let mut tx = generate_random_tx(opts.nonce);
            tx.set_gas_price(69_420_000_000_000u128); // 69_420 gwei
            transaction_signer.fill_transaction(&mut tx, None).await?;
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

            if let Err(e) = events_client
                .preconf_requested(PreconfRequestedEvent {
                    protocol_id: proto.to_string(),
                    tx_hash: tx_hash.clone(),
                    timestamp: unix_millis(),
                    slot: event.slot + 1, // target_slot,
                    validator_index: next_proposer.validator_index as u64,
                    endpoint: endpoint.clone(),
                })
                .await
            {
                tracing::error!(error = ?e, "Failed publishing preconf requested event");
            }

            println!();
            let start = Instant::now();
            let msg = format!(
                "Sending preconf request to {}, protocol: {}",
                endpoint, proto
            );
            info!("{}", msg.bold());
            debug!("body: {}", serde_json::to_string(&request)?);

            let Ok(response) = send_preconf_to(&endpoint, request).await else {
                tracing::error!("Failed to send preconf request");
                continue;
            };

            let msg = format!("Transaction preconfirmed: {}", tx_hash).bold();
            info!(elapsed = ?start.elapsed(), "{}", msg);
            println!();
            debug!("Response: {:?}", response.text().await?);

            if !is_vanilla {
                if let Err(e) = events_client
                    .preconf_responded(PreconfRespondedEvent {
                        protocol_id: proto.to_string(),
                        tx_hash: tx_hash.clone(),
                        timestamp: unix_millis(),
                        slot: event.slot + 1, // target_slot,
                        validator_index: next_proposer.validator_index as u64,
                        endpoint: endpoint.clone(),
                    })
                    .await
                {
                    tracing::error!(error = ?e, "Failed publishing preconf requested event");
                }
            } else {
                tracing::warn!("Skipping preconf responded event for vanilla proposer");
            }

            let curr = preconf_cache.entry(event.slot).or_default();
            curr.push(tx_hash);
        }

        if let Some(block) = eth_provider.get_block(BlockNumber::Latest).await? {
            let number = block.number.unwrap().as_u64();

            // let mut graffiti = String::from_utf8_lossy(&block.extra_data).to_string();
            // graffiti = if graffiti.contains("Illuminate") {
            //     "Bolt Builder".to_string()
            // } else {
            //     graffiti
            // };

            tracing::info!(
                new_block = number,
                "Checking block for confirmed preconfs..."
            );

            let vix = next_proposer.validator_index as u64;
            let events_client_clone = events_client.clone();
            let confirmed = preconf_cache.remove(&(event.slot)).unwrap_or_default();
            tokio::spawn(async move {
                tracing::info!(txs = ?confirmed, "Sending confirmation event");

                if let Err(e) = events_client_clone
                    .preconfs_confirmed(PreconfsConfirmedEvent {
                        protocol_id: proto.to_string(),
                        timestamp: unix_millis(),
                        slot: event.slot + 1,
                        validator_index: vix,
                        endpoint: endpoint.clone(),
                        tx_hashes: confirmed,
                        block_number: number,
                        block_hash: format!("{:?}", block.hash.unwrap()),
                        graffiti: String::from_utf8_lossy(&block.extra_data).to_string(),
                    })
                    .await
                {
                    tracing::error!(error = ?e, "Failed publishing preconf requested event");
                }
            });
        } else {
            tracing::error!(hash = ?event.block, "Block not found, skipping...");
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

    let status = response.status();

    if !status.is_success() {
        tracing::error!("{}", response.text().await?);
        return Err(Error::RequestFailed(status.as_u16()));
    }

    Ok(response)
}

fn generate_random_tx(nonce: Option<u16>) -> TypedTransaction {
    let mut tx = TransactionRequest::new()
        .to("0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD")
        .value("0x69420")
        .chain_id(67707)
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

#[allow(dead_code)]
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

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}
