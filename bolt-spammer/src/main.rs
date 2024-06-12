use std::{
    collections::HashSet,
    fmt,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use beacon_api_client::ProposerDuty;
use clap::{Parser, ValueEnum};
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

    let wallet = LocalWallet::from_str(&opts.private_key)?;
    let eth_provider = Arc::new(Provider::<Http>::try_from(config.execution_api)?);
    let transaction_signer = SignerMiddleware::new(eth_provider.clone(), wallet);

    let events_client = config.events_api.map(EventsClient::new);

    let mut preconf_cache = HashSet::new();

    let target = format!("{}/eth/v1/events?topics=head", config.beacon_api);

    let client = EventClient::default();

    let mut sub = client.subscribe::<HeadEvent>(&target).await?;

    let lookahead_provider = LookaheadProvider::new(&config.beacon_api);
    let mut lookahead = lookahead_provider.get_current_lookahead().await?;
    let lookahead_size = lookahead.len();
    tracing::info!(lookahead_size, "Proposer lookahead fetched");

    // Start listening to head events
    while let Some(event) = sub.next().await {
        let event = event?;
        tracing::info!(block_hash = ?event.block, "New head slot: {}", event.slot);

        if event.epoch_transition {
            lookahead = lookahead_provider.get_current_lookahead().await?;
            tracing::info!("Epoch transition, fetched new proposer lookahead...");
        }

        let mut tx = generate_random_tx(opts.nonce);
        tx.set_gas_price(69_420_000_000_000u128); // 69_420 gwei
        transaction_signer.fill_transaction(&mut tx, None).await?;

        let Some(next_proposer) = lookahead.iter().find(|duty| duty.slot == event.slot + 1) else {
            tracing::warn!("At end of epoch, waiting");
            continue;
        };

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
                        continue;
                    }
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

        if let Some(ref events_client) = events_client {
            if let Err(e) = events_client
                .preconf_requested(PreconfRequestedEvent {
                    protocol_id: proto.to_string(),
                    tx_hash: tx_hash.clone(),
                    timestamp: unix_millis(),
                    slot: target_slot,
                    validator_index: next_proposer.validator_index as u64,
                    endpoint: endpoint.clone(),
                })
                .await
            {
                tracing::error!(error = ?e, "Failed publishing preconf requested event");
            }
        }

        let response = send_preconf_to(&endpoint, request).await?;

        info!("Response: {:?}", response.text().await?);

        if let Some(ref events_client) = events_client {
            if let Err(e) = events_client
                .preconf_responded(PreconfRespondedEvent {
                    protocol_id: proto.to_string(),
                    tx_hash: tx_hash.clone(),
                    timestamp: unix_millis(),
                    slot: target_slot,
                    validator_index: next_proposer.validator_index as u64,
                    endpoint: endpoint.clone(),
                })
                .await
            {
                tracing::error!(error = ?e, "Failed publishing preconf requested event");
            }
        }

        preconf_cache.insert(tx_hash);

        if let Some(block) = eth_provider.get_block(BlockNumber::Latest).await? {
            let number = block.number.unwrap().as_u64();
            let graffiti = String::from_utf8_lossy(&block.extra_data).to_string();
            tracing::info!(number, "Checking block for confirmed preconfs...");
            let mut confirmed = Vec::new();

            for hash in block.transactions {
                let hash_str = format!("{:?}", hash);

                if preconf_cache.remove(&hash_str) {
                    tracing::info!(number, slot = event.slot, graffiti, tx_hash = ?hash, "PRECONF INCLUDED IN BLOCK");
                    confirmed.push(hash_str);
                }
            }

            if confirmed.is_empty() {
                continue;
            }

            if let Some(ref events_client) = events_client {
                if let Err(e) = events_client
                    .preconfs_confirmed(PreconfsConfirmedEvent {
                        protocol_id: proto.to_string(),
                        timestamp: unix_millis(),
                        slot: target_slot,
                        validator_index: next_proposer.validator_index as u64,
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
            }
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

    Ok(response)
}

fn generate_random_tx(nonce: Option<u16>) -> TypedTransaction {
    let mut tx = Eip1559TransactionRequest::new()
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
