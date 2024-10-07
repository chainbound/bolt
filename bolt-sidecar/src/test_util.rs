use alloy::{
    eips::eip2718::Encodable2718,
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, U256},
    rpc::types::TransactionRequest,
    signers::{
        k256::{ecdsa::SigningKey as K256SigningKey, SecretKey as K256SecretKey},
        local::PrivateKeySigner,
        Signer,
    },
};
use alloy_node_bindings::{Anvil, AnvilInstance};
use blst::min_pk::SecretKey;
use cb_common::signature::sign_commit_boost_root;
use ethereum_consensus::crypto::{PublicKey, Signature};
use rand::Rng;
use reth_primitives::PooledTransactionsElement;
use secp256k1::Message;
use tracing::warn;

use crate::{
    crypto::{ecdsa::SignableECDSA, SignableBLS},
    primitives::{
        CommitmentRequest, ConstraintsMessage, DelegationMessage, FullTransaction,
        InclusionRequest, RevocationMessage, SignedConstraints, SignedDelegation, SignedRevocation,
    },
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
        warn!("ENGINE_JWT not found in environment variables");
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
        .with_max_priority_fee_per_gas(1_000_000_000) // 1 gwei
        .with_max_fee_per_gas(20_000_000_000)
}

/// Create a default BLS secret key
pub(crate) fn test_bls_secret_key() -> SecretKey {
    SecretKey::key_gen(&[0u8; 32], &[]).unwrap()
}

/// Arbitrary bytes that can be signed with both ECDSA and BLS keys
pub(crate) struct TestSignableData {
    pub data: [u8; 32],
}

impl SignableBLS for TestSignableData {
    fn digest(&self) -> [u8; 32] {
        self.data
    }
}

impl SignableECDSA for TestSignableData {
    fn digest(&self) -> Message {
        // pad the data to 32 bytes
        let as_32 = if self.data.len() < 32 {
            let mut padded = [0u8; 32];
            padded[..self.data.len()].copy_from_slice(&self.data);
            padded
        } else {
            self.data
        };

        Message::from_digest_slice(&as_32).expect("valid message")
    }
}

/// Create a valid signed commitment request for testing purposes
/// from the given transaction, private key of the sender, and slot.
pub(crate) async fn create_signed_commitment_request(
    txs: &[TransactionRequest],
    sk: &K256SecretKey,
    slot: u64,
) -> eyre::Result<CommitmentRequest> {
    let sk = K256SigningKey::from_slice(sk.to_bytes().as_slice())?;
    let signer = PrivateKeySigner::from_signing_key(sk.clone());
    let wallet = EthereumWallet::from(signer.clone());

    let mut full_txs = Vec::with_capacity(txs.len());
    for tx in txs {
        let tx_signed = tx.clone().build(&wallet).await?;
        let raw_encoded = tx_signed.encoded_2718();
        let tx_pooled = PooledTransactionsElement::decode_enveloped(&mut raw_encoded.as_slice())?;
        full_txs.push(FullTransaction::from(tx_pooled));
    }
    let mut request = InclusionRequest { txs: full_txs, slot, signature: None, signer: None };

    request.recover_signers()?;

    let signature = signer.sign_hash(&request.digest()).await?;
    request.set_signature(signature);
    request.set_signer(signer.address());

    Ok(CommitmentRequest::Inclusion(request))
}

fn random_constraints(count: usize) -> Vec<FullTransaction> {
    // Random inclusion request
    let json_req = r#"{
        "slot": 10,
        "txs": [
        "0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4",
        "0x02f9017b8501a2140cff8303dec685012a05f2008512a05f2000830249f094843669e5220036eddbaca89d8c8b5b82268a0fc580b901040cc7326300000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000022006292538e66f0000000000000000000000005ba38f2c245618e39f6fa067bf1dec304e73ff3c00000000000000000000000092f0ee29e6e1bf0f7c668317ada78f5774a6cb7f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000003fac6482aee49bf58515be2d3fb58378a8497cc9000000000000000000000000c6cc140787b02ae479a10e41169607000c0d44f6c080a00cf74c45dbe9ee1fb923118ec5ce9db8f88cd651196ed3f9d4f8f2a65827e611a04a6bc1d49a7e18b7c92e8f3614cae116b1832ceb311c81d54b2c87de1545f68f",
        "0x02f8708501a2140cff82012f800782520894b6c402298fcb88039bbfde70f5ace791f18cfac88707131d70870dc880c080a03aab1b17ecf28f85de43c7733611759b87d25ba885babacb6b4c625d715415eea03fb52cb7744ccb885906e42f6b9cf82e74b47a4b4b4072af2aa52a8dc472236e"
        ]
    }"#;

    let req: InclusionRequest = serde_json::from_str(json_req).unwrap();

    req.txs.iter().take(count).cloned().collect()
}

#[tokio::test]
async fn generate_test_data() {
    let sk = test_bls_secret_key();
    let pk = sk.sk_to_pk();

    println!("Validator Public Key: {}", hex::encode(pk.to_bytes()));

    // Generate a delegatee's BLS secret key and public key
    let delegatee_ikm: [u8; 32] = rand::thread_rng().gen();
    let delegatee_sk =
        SecretKey::key_gen(&delegatee_ikm, &[]).expect("Failed to generate delegatee secret key");
    let delegatee_pk = delegatee_sk.sk_to_pk();

    // Prepare a Delegation message
    let delegation_msg = DelegationMessage {
        validator_pubkey: PublicKey::try_from(pk.to_bytes().as_slice())
            .expect("Failed to convert validator public key"),
        delegatee_pubkey: PublicKey::try_from(delegatee_pk.to_bytes().as_slice())
            .expect("Failed to convert delegatee public key"),
    };

    let digest = SignableBLS::digest(&delegation_msg);

    // Sign the Delegation message
    let delegation_signature = sign_commit_boost_root(cb_common::types::Chain::Mainnet, &sk, digest);

    // Create SignedDelegation
    let signed_delegation = SignedDelegation {
        message: delegation_msg,
        signature: Signature::try_from(delegation_signature.as_ref())
            .expect("Failed to convert delegation signature"),
    };

    // Output SignedDelegation
    println!("{}", serde_json::to_string_pretty(&signed_delegation).unwrap());

    // Prepare a revocation message
    let revocation_msg = RevocationMessage {
        validator_pubkey: PublicKey::try_from(pk.to_bytes().as_slice())
            .expect("Failed to convert validator public key"),
        delegatee_pubkey: PublicKey::try_from(delegatee_pk.to_bytes().as_slice())
            .expect("Failed to convert delegatee public key"),
    };

    let digest = SignableBLS::digest(&revocation_msg);

    // Sign the Revocation message
    let revocation_signature = sign_commit_boost_root(cb_common::types::Chain::Mainnet, &sk, digest);

    // Create SignedRevocation
    let signed_revocation = SignedRevocation {
        message: revocation_msg,
        signature: Signature::try_from(revocation_signature.as_ref())
            .expect("Failed to convert revocation signature"),
    };

    // Output SignedRevocation
    println!("{}", serde_json::to_string_pretty(&signed_revocation).unwrap());

    let transactions = random_constraints(1);

    // Prepare a ConstraintsMessage
    let constraints_msg = ConstraintsMessage {
        pubkey: PublicKey::try_from(pk.to_bytes().as_slice())
            .expect("Failed to convert validator public key"),
        slot: 32,
        top: true,
        transactions,
    };

    let digest = SignableBLS::digest(&constraints_msg);

    // Sign the ConstraintsMessage
    let constraints_signature = sign_commit_boost_root(cb_common::types::Chain::Mainnet, &sk, digest);

    // Create SignedConstraints
    let signed_constraints =
        SignedConstraints { message: constraints_msg, signature: constraints_signature };

    // Output SignedConstraints
    println!("{}", serde_json::to_string_pretty(&signed_constraints).unwrap());
}
