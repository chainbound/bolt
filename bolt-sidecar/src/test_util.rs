use alloy::{
    eips::eip2718::Encodable2718,
    network::{EthereumWallet, TransactionBuilder},
    primitives::{keccak256, Address, B256, U256},
    rpc::types::TransactionRequest,
    signers::{
        k256::{ecdsa::SigningKey as K256SigningKey, SecretKey as K256SecretKey},
        local::PrivateKeySigner,
        Signer,
    },
};
use alloy_node_bindings::{Anvil, AnvilInstance};
use blst::min_pk::SecretKey;
use reth_primitives::PooledTransactionsElement;
use secp256k1::Message;

use crate::{
    crypto::{ecdsa::SignableECDSA, SignableBLS},
    primitives::{CommitmentRequest, InclusionRequest},
    Config,
};

/// The URL of the test execution client HTTP API.
///
/// NOTE: this DNS is only available through the Chainbound Tailnet
const EXECUTION_API_URL: &str = "http://remotebeast:8545";

/// The URL of the test beacon client HTTP API.
///
/// NOTE: this DNS is only available through the Chainbound Tailnet
const BEACON_API_URL: &str = "http://remotebeast:3500";

/// The URL of the test engine client HTTP API.
///
/// NOTE: this DNS is only available through the Chainbound Tailnet
const ENGINE_API_URL: &str = "http://remotebeast:8551";

/// Check if the test execution client is reachable by sending a GET request to it.
pub(crate) async fn try_get_execution_api_url() -> Option<&'static str> {
    if reqwest::get(EXECUTION_API_URL).await.is_ok() {
        Some(EXECUTION_API_URL)
    } else {
        None
    }
}

/// Check if the test engine client is reachable by sending a GET request to it.
pub(crate) async fn try_get_engine_api_url() -> Option<&'static str> {
    if reqwest::get(ENGINE_API_URL).await.is_ok() {
        Some(ENGINE_API_URL)
    } else {
        None
    }
}

/// Check if the test beacon client is reachable by sending a GET request to it.
pub(crate) async fn try_get_beacon_api_url() -> Option<&'static str> {
    if reqwest::get(BEACON_API_URL).await.is_ok() {
        Some(BEACON_API_URL)
    } else {
        None
    }
}

/// Return a mock configuration for testing purposes. Contains:
/// - The URL of the test execution client HTTP API.
/// - The URL of the test engine client HTTP API.
/// - The URL of the test beacon client HTTP API.
/// - The JWT token used to authenticate with the test engine API
/// - The default values for the remaining configuration fields.
///
/// If any of the above values can't be found, the function will return `None`.
pub(crate) async fn get_test_config() -> Option<Config> {
    let _ = dotenvy::dotenv();

    let Some(jwt) = std::env::var("ENGINE_JWT").ok() else {
        tracing::warn!("ENGINE_JWT not found in environment variables");
        return None;
    };

    let execution = try_get_execution_api_url().await?;
    let beacon = try_get_beacon_api_url().await?;
    let engine = try_get_engine_api_url().await?;

    Some(Config {
        execution_api_url: execution.parse().ok()?,
        engine_api_url: engine.parse().ok()?,
        beacon_api_url: beacon.parse().ok()?,
        jwt_hex: jwt,
        ..Default::default()
    })
}

/// Launch a local instance of the Anvil test chain.
pub(crate) fn launch_anvil() -> AnvilInstance {
    Anvil::new().block_time(1).chain_id(1337).spawn()
}

/// Create a default transaction template to use for tests
pub(crate) fn default_test_transaction(sender: Address, nonce: Option<u64>) -> TransactionRequest {
    TransactionRequest::default()
        .with_from(sender)
        // Burn it
        .with_to(Address::ZERO)
        .with_chain_id(1337)
        .with_nonce(nonce.unwrap_or(0))
        .with_value(U256::from(100))
        .with_gas_limit(21_000)
        .with_max_priority_fee_per_gas(1_000_000_000)
        .with_max_fee_per_gas(20_000_000_000)
}

/// Create a default BLS secret key
pub(crate) fn test_bls_secret_key() -> SecretKey {
    SecretKey::key_gen(&[0u8; 32], &[]).unwrap()
}

/// Arbitrary bytes that can be signed with both ECDSA and BLS keys
pub(crate) struct TestSignableData {
    pub data: Vec<u8>,
}

impl SignableBLS for TestSignableData {
    fn digest(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl SignableECDSA for TestSignableData {
    fn digest(&self) -> Message {
        // pad the data to 32 bytes
        let as_32 = if self.data.len() < 32 {
            let mut padded = vec![0; 32];
            padded[..self.data.len()].copy_from_slice(&self.data);
            padded
        } else {
            self.data.clone()
        };

        Message::from_digest_slice(as_32.as_slice()).expect("valid message")
    }
}

/// Create a valid signed commitment request for testing purposes
/// from the given transaction, private key of the sender, and slot.
pub(crate) async fn create_signed_commitment_request(
    tx: TransactionRequest,
    sk: &K256SecretKey,
    slot: u64,
) -> eyre::Result<CommitmentRequest> {
    let sk = K256SigningKey::from_slice(sk.to_bytes().as_slice())?;
    let signer = PrivateKeySigner::from_signing_key(sk.clone());
    let wallet = EthereumWallet::from(signer.clone());

    let tx_signed = tx.build(&wallet).await?;
    let raw_encoded = tx_signed.encoded_2718();
    let tx_pooled = PooledTransactionsElement::decode_enveloped(&mut raw_encoded.as_slice())?;

    let tx_hash = tx_pooled.hash();

    let message_digest = {
        let mut data = Vec::new();
        data.extend_from_slice(&slot.to_le_bytes());
        data.extend_from_slice(tx_hash.as_slice());
        B256::from(keccak256(data))
    };

    let signature = signer.sign_hash(&message_digest).await?;

    Ok(CommitmentRequest::Inclusion(InclusionRequest {
        tx: tx_pooled,
        slot,
        signature,
        sender: signer.address(),
    }))
}
