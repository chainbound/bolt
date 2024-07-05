use std::{str::FromStr, sync::Arc};

use beacon_api_client::{mainnet::Client as BeaconApiClient, BlockId};
use bolt_spammer_helder::{
    types::Registrant,
    utils::{
        current_epoch, generate_random_tx, prepare_rpc_request, sign_transaction,
        try_parse_url_from_token,
    },
};
use clap::Parser;
use ethers::{
    abi::{Abi, Token},
    contract::{Contract, ContractError},
    middleware::{Middleware, SignerMiddleware},
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
    types::{transaction::eip2718::TypedTransaction, Address, Eip1559TransactionRequest, H256},
    utils::hex,
};
use eyre::{eyre, Context, OptionExt, Result};
use rand::{thread_rng, Rng};
use reqwest::Url;
use serde_json::Value;
use tracing::info;

#[derive(Parser)]
struct Opts {
    #[clap(
        short = 'p',
        long,
        default_value = "https://rpc.helder-devnets.xyz",
        env
    )]
    el_provider_url: String,
    #[clap(short = 'c', long, default_value = "http://localhost:4000", env)]
    beacon_client_url: Url,
    #[clap(
        short = 'r',
        long,
        default_value = "0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9",
        env
    )]
    registry_address: Address,
    #[clap(short = 'k', long, env)]
    private_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("Starting bolt-spammer-helder");

    let path = dotenvy::dotenv()?;
    tracing::info!("Loaded environment variables from {:?}", path);
    let opts = Opts::parse();

    let wallet = LocalWallet::from_str(&opts.private_key)?;
    let eth_provider = Arc::new(Provider::<Http>::try_from(opts.el_provider_url)?);
    let transaction_signer = SignerMiddleware::new(eth_provider.clone(), wallet);

    let beacon_api_client = BeaconApiClient::new(opts.beacon_client_url);

    let contract_abi: Abi = serde_json::from_str(&std::fs::read_to_string("./registry_abi.json")?)?;
    let registry_contract = Contract::new(opts.registry_address, contract_abi, eth_provider);

    let current_epoch = current_epoch(&beacon_api_client).await?;
    let proposer_duties = beacon_api_client
        .get_proposer_duties(current_epoch)
        .await?
        .1;

    let mut slot = 0;
    let mut proposer_rpc = String::new();
    for duty in proposer_duties {
        let res = registry_contract
            .method::<u64, Token>("getOperatorForValidator", duty.validator_index as u64)?
            .call()
            .await;
        match res {
            Ok(token_raw) => {
                slot = duty.slot;
                proposer_rpc = try_parse_url_from_token(token_raw)?;
                tracing::info!(
                    "Pre-confirmation will be sent for slot {} to validator with index {} at url {}",
                    duty.slot,
                    duty.validator_index,
                    proposer_rpc,
                );
                break;
            }
            // Such validator index is not registered, continue
            Err(ContractError::Revert(_)) => {
                tracing::warn!(
                    "Validator index {} not registered, skipping",
                    duty.validator_index
                );
                continue;
            }
            Err(e) => {
                return Err(eyre!(
                    "unexpected error while calling registry contract: {:?}",
                    e
                ));
            }
        }
    }

    if slot == 0 {
        return Err(eyre!(
            "no registered validators found in the lookahead for epoch {}",
            current_epoch
        ));
    };

    let mut tx = generate_random_tx();
    tx.set_gas_price(69_420_000_000_000u128); // 69_420 gwei
    transaction_signer.fill_transaction(&mut tx, None).await?;

    let current_slot = 0;

    let (tx_hash, tx_rlp) = sign_transaction(transaction_signer.signer(), tx).await?;

    let message_digest = {
        let mut data = Vec::new();
        data.extend_from_slice(&slot.to_le_bytes());
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
            "slot": slot,
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
