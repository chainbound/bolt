use std::str::FromStr;

use alloy::{
    consensus::{BlobTransactionSidecar, SidecarBuilder, SimpleCoder},
    hex,
    network::TransactionBuilder,
    primitives::{keccak256, Address, B256, U256},
    rpc::types::TransactionRequest,
    signers::{local::PrivateKeySigner, Signer},
};
use beacon_api_client::{mainnet::Client as BeaconApiClient, BlockId, ProposerDuty};
use rand::{thread_rng, Rng};
use serde_json::Value;

pub const NOICE_GAS_PRICE: u128 = 69_420_000u128;
pub const DEAD_ADDRESS: &str = "0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD";

/// Generates random ETH transfer to `DEAD_ADDRESS` with a random payload.
pub fn generate_random_tx() -> TransactionRequest {
    TransactionRequest::default()
        .with_to(Address::from_str(DEAD_ADDRESS).unwrap())
        .with_value(U256::from(thread_rng().gen_range(1..100)))
        .with_gas_limit(1000000u128)
        .with_gas_price(NOICE_GAS_PRICE)
}

/// Generate random transaction with blob (eip4844)
pub fn generate_random_blob_tx() -> TransactionRequest {
    let sidecar: SidecarBuilder<SimpleCoder> = SidecarBuilder::from_slice(b"Blobs are fun!");
    let sidecar: BlobTransactionSidecar = sidecar.build().unwrap();

    TransactionRequest::default()
        .with_to(Address::from_str(DEAD_ADDRESS).unwrap())
        .with_value(U256::from(100))
        .with_max_fee_per_blob_gas(100u128)
        .max_fee_per_gas(100u128)
        .max_priority_fee_per_gas(50u128)
        .with_gas_limit(1_000_000u128)
        .with_blob_sidecar(sidecar)
}

pub fn prepare_rpc_request(method: &str, params: Vec<Value>) -> Value {
    serde_json::json!({
        "id": "1",
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
}

/// Returns the current slot from the beacon client
pub async fn get_current_slot(beacon_api_client: &BeaconApiClient) -> eyre::Result<u64> {
    Ok(beacon_api_client.get_beacon_header(BlockId::Head).await?.header.message.slot)
}

pub async fn get_proposer_duties(
    beacon_api_client: &BeaconApiClient,
    current_slot: u64,
    current_epoch: u64,
) -> eyre::Result<Vec<ProposerDuty>> {
    Ok(beacon_api_client
        .get_proposer_duties(current_epoch)
        .await?
        .1
        .into_iter()
        .filter(|duty| duty.slot > current_slot)
        .collect::<Vec<_>>())
}

pub async fn sign_request(
    tx_hashes: Vec<&B256>,
    target_slot: u64,
    wallet: &PrivateKeySigner,
) -> eyre::Result<String> {
    let digest = {
        let mut data = Vec::new();
        let hashes = tx_hashes.iter().map(|hash| hash.as_slice()).collect::<Vec<_>>().concat();
        data.extend_from_slice(&hashes);
        data.extend_from_slice(target_slot.to_le_bytes().as_slice());
        keccak256(data)
    };

    let signature = hex::encode(wallet.sign_hash(&digest).await?.as_bytes());

    Ok(format!("{}:0x{}", wallet.address(), signature))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::{
        primitives::{keccak256, Signature, B256},
        signers::local::PrivateKeySigner,
    };

    use crate::sign_request;

    #[tokio::test]
    async fn test_sign_request() -> eyre::Result<()> {
        let wallet = PrivateKeySigner::random();
        let tx_hash =
            B256::from_str("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
        let target_slot = 42;

        let signature = sign_request(vec![&tx_hash], target_slot, &wallet).await?;
        let parts: Vec<&str> = signature.split(':').collect();

        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], wallet.address().to_string());
        assert_eq!(parts[1].len(), 130);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_signature() -> eyre::Result<()> {
        // Randomly generated private key
        let private_key = "0xfa4c3c87627a58684fb519f7b01a31ef31e56f414e8aa56a15f574381a5a7a9c";
        let tx_hash = "0x6938dbd0649ce26af79b0cca677b493257bd87c17d25ff717feba33c8b3920b3";
        let expected_signature = "0x10386a2aF29854954645C9710A038AcF4B2F1752:0x8db9bbcc1db5257c80138bd1df0185305918dbc8a607f63458ea885a6ccce5177a73417d693953b9f5c017a927e9c8acbf24c05b09a55f1f3fa83db57931ed9e1c";
        let target_slot = 254464;

        let wallet = PrivateKeySigner::from_str(private_key)?;
        let tx_hash = B256::from_str(tx_hash)?;

        let signature = sign_request(vec![&tx_hash], target_slot, &wallet).await?;

        assert_eq!(signature, expected_signature);

        let expected_signer = expected_signature.split(':').next().unwrap();
        let expected_sig = expected_signature.split(':').last().unwrap();
        let sig = Signature::from_str(expected_sig)?;

        // recompute the prehash again
        let digest = {
            let mut data = Vec::new();
            data.extend_from_slice(tx_hash.as_slice());
            data.extend_from_slice(target_slot.to_le_bytes().as_slice());
            keccak256(data)
        };

        let recovered_address = sig.recover_address_from_prehash(&digest)?;
        assert_eq!(recovered_address, wallet.address());
        assert_eq!(recovered_address.to_string(), expected_signer);

        Ok(())
    }
}
