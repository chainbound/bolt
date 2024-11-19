use std::collections::HashMap;

use alloy::{
    network::EthereumWallet,
    primitives::{address, Address},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;
use eyre::Context;

use crate::{
    cli::{Chain, RegisterCommand},
    common::hash::compress_bls_pubkey,
};

#[derive(Debug, PartialEq, Eq, Hash)]
enum BoltContract {
    Validators,
}

impl RegisterCommand {
    /// Run the `delegate` command.
    pub async fn run(self) -> eyre::Result<()> {
        let bolt_validators_address = bolt_validators_address(self.chain);

        let pubkeys_file = std::fs::File::open(&self.pubkeys_path)?;
        let keys: Vec<BlsPublicKey> = serde_json::from_reader(pubkeys_file)?;
        let pubkey_hashes: Vec<_> = keys.iter().map(compress_bls_pubkey).collect();

        let wallet: PrivateKeySigner =
            self.admin_private_key.parse().wrap_err("invalid private key")?;
        let transaction_signer = EthereumWallet::from(wallet);
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(self.rpc_url.clone());

        let bolt_validators = BoltValidatorsContract::new(bolt_validators_address, provider);

        let call = bolt_validators.batchRegisterValidatorsUnsafe(
            pubkey_hashes,
            self.max_committed_gas_limit,
            self.authorized_operator,
        );

        let result = call.send().await?.watch().await?;

        println!("transaction hash: {:?}", result);

        Ok(())
    }
}

// PERF: this should be done at compile time
fn deployments() -> HashMap<Chain, HashMap<BoltContract, Address>> {
    let mut deployments = HashMap::new();
    let mut holesky_deployments = HashMap::new();
    holesky_deployments
        .insert(BoltContract::Validators, address!("47D2DC1DE1eFEFA5e6944402f2eda3981D36a9c8"));
    deployments.insert(Chain::Holesky, holesky_deployments);

    deployments
}

fn bolt_validators_address(chain: Chain) -> Address {
    *deployments()
        .get(&chain)
        .unwrap_or_else(|| panic!("{:?} chain supported", chain))
        .get(&BoltContract::Validators)
        .expect("Validators contract address not found")
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltValidatorsContract {
        /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
        /// @dev This function allows anyone to register a list of Validators.
        /// @param pubkeyHashes List of BLS public key hashes for the Validators to be registered
        /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
        /// @param authorizedOperator The address of the authorized operator
        function batchRegisterValidatorsUnsafe(bytes20[] calldata pubkeyHashes, uint32 maxCommittedGasLimit, address authorizedOperator);

        error KeyNotFound();
        error InvalidQuery();
        #[derive(Debug)]
        error ValidatorDoesNotExist(bytes20 pubkeyHash);
        error InvalidAuthorizedOperator();
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{Address, U256},
        providers::{ext::AnvilApi, Provider, ProviderBuilder},
        signers::k256::ecdsa::SigningKey,
    };

    use crate::cli::RegisterCommand;

    #[tokio::test]
    async fn test_register_validators() {
        let rpc_url = "https://holesky.drpc.org";
        let provider = ProviderBuilder::new().on_anvil_with_config(|anvil| anvil.fork(rpc_url));
        let anvil_url = provider.client().transport().url();

        let mut rnd = rand::thread_rng();
        let secret_key = SigningKey::random(&mut rnd);
        let account = Address::from_private_key(&secret_key);

        provider.anvil_set_balance(account, U256::from(u64::MAX)).await.expect("set balance");

        let command = RegisterCommand {
            chain: crate::cli::Chain::Holesky,
            max_committed_gas_limit: 30_000_000,
            admin_private_key: format!("{:x}", secret_key.to_bytes()),
            authorized_operator: account,
            pubkeys_path: "./test_data/pubkeys.json".parse().unwrap(),
            rpc_url: anvil_url.parse().unwrap(),
        };

        command.run().await.expect("run command");
    }
}
