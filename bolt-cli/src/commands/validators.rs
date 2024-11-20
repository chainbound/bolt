use alloy::providers::{Provider, ProviderBuilder};
use ethereum_consensus::crypto::PublicKey as BlsPublicKey;

use crate::{
    cli::{Chain, ValidatorsCommand, ValidatorsSubcommand},
    common::{hash::compress_bls_pubkey, signing::wallet_from_sk},
    contracts::{bolt::BoltValidators, deployments_for_chain},
};

impl ValidatorsCommand {
    pub async fn run(self) -> eyre::Result<()> {
        match self.subcommand {
            ValidatorsSubcommand::Register {
                max_committed_gas_limit,
                pubkeys_path,
                admin_private_key,
                authorized_operator,
                rpc_url,
            } => {
                let wallet = wallet_from_sk(admin_private_key)?;

                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(wallet)
                    .on_http(rpc_url.clone());

                let chain_id = provider.get_chain_id().await?;
                let chain = Chain::from_id(chain_id)
                    .unwrap_or_else(|| panic!("chain id {} not supported", chain_id));

                let bolt_validators_address = deployments_for_chain(chain).bolt.validators;

                let pubkeys_file = std::fs::File::open(&pubkeys_path)?;
                let keys: Vec<BlsPublicKey> = serde_json::from_reader(pubkeys_file)?;
                let pubkey_hashes: Vec<_> = keys.iter().map(compress_bls_pubkey).collect();

                let bolt_validators = BoltValidators::new(bolt_validators_address, provider);

                let call = bolt_validators.batchRegisterValidatorsUnsafe(
                    pubkey_hashes,
                    max_committed_gas_limit,
                    authorized_operator,
                );

                let result = call.send().await?;
                println!("Transaction submitted successfully, waiting for inclusion");
                let result = result.watch().await?;
                println!("Transaction included. Transaction hash: {:?}", result);

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{Address, U256},
        providers::{ext::AnvilApi, Provider, ProviderBuilder},
        signers::k256::ecdsa::SigningKey,
    };

    use crate::cli::{ValidatorsCommand, ValidatorsSubcommand};

    #[tokio::test]
    async fn test_register_validators() {
        let rpc_url = "https://holesky.drpc.org";
        let provider = ProviderBuilder::new().on_anvil_with_config(|anvil| anvil.fork(rpc_url));
        let anvil_url = provider.client().transport().url();

        let mut rnd = rand::thread_rng();
        let secret_key = SigningKey::random(&mut rnd);
        let account = Address::from_private_key(&secret_key);

        provider.anvil_set_balance(account, U256::from(u64::MAX)).await.expect("set balance");

        let command = ValidatorsCommand {
            subcommand: ValidatorsSubcommand::Register {
                max_committed_gas_limit: 30_000_000,
                admin_private_key: format!("{:x}", secret_key.to_bytes()),
                authorized_operator: account,
                pubkeys_path: "./test_data/pubkeys.json".parse().unwrap(),
                rpc_url: anvil_url.parse().unwrap(),
            },
        };

        command.run().await.expect("run command");
    }
}
