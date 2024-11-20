use crate::{
    cli::{
        Chain, EigenLayerSubcommand, OperatorsCommand, OperatorsSubcommand, SymbioticSubcommand,
    },
    common::signing::wallet_from_sk,
    contracts::{
        deployments_for_chain,
        eigenlayer::{IStrategy::IStrategyInstance, IStrategyManager::IStrategyManagerInstance},
        erc20::IERC20::IERC20Instance,
        strategy_to_address,
    },
};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};

impl OperatorsCommand {
    pub async fn run(self) -> eyre::Result<()> {
        match self.subcommand {
            OperatorsSubcommand::EigenLayer { subcommand } => match subcommand {
                EigenLayerSubcommand::DepositIntoStrategy {
                    rpc_url,
                    strategy,
                    amount,
                    operator_private_key,
                } => {
                    let wallet = wallet_from_sk(operator_private_key)?;

                    let provider = ProviderBuilder::new()
                        .with_recommended_fillers()
                        .wallet(wallet)
                        .on_http(rpc_url.clone());

                    let chain_id = provider.get_chain_id().await?;
                    let chain = Chain::from_id(chain_id)
                        .unwrap_or_else(|| panic!("chain id {} not supported", chain_id));

                    let deployments = deployments_for_chain(chain);

                    let strategy_address =
                        strategy_to_address(strategy, deployments.eigen_layer.supported_strategies);
                    let strategy_contract =
                        IStrategyInstance::new(strategy_address, provider.clone());
                    let strategy_manager_address = deployments.eigen_layer.strategy_manager;
                    let strategy_manager =
                        IStrategyManagerInstance::new(strategy_manager_address, provider.clone());

                    let token = strategy_contract.underlyingToken().call().await?.token;
                    println!("Token address: {:?}", token);

                    let token_erc20 = IERC20Instance::new(token, provider.clone());

                    let balance = token_erc20
                        .balanceOf(provider.clone().default_signer_address())
                        .call()
                        .await?
                        ._0;
                    println!("Balance: {:?}", balance);

                    let result =
                        token_erc20.approve(strategy_manager_address, amount).send().await?;
                    println!(
                        "Approving transfer of {} {:?}, waiting for inclusion",
                        amount, strategy
                    );
                    let result = result.watch().await?;
                    println!("Approval transaction included. Transaction hash: {:?}", result);

                    let allowance = token_erc20
                        .allowance(
                            provider.clone().default_signer_address(),
                            strategy_manager_address,
                        )
                        .call()
                        .await?
                        ._0;
                    println!("Allowance: {:?}", allowance);

                    let result = strategy_manager
                        .depositIntoStrategy(strategy_address, token, amount)
                        .send()
                        .await?;

                    println!("Submitted transaction to deposit into strategy successfully, waiting for inclusion");
                    let result = result.watch().await;
                    println!("Deposit transaction included. Transaction hash: {:?}", result);

                    Ok(())
                }
                EigenLayerSubcommand::RegisterIntoBoltAVS {
                    rpc_url,
                    operator_rpc,
                    salt,
                    expiry,
                    operator_private_key,
                } => {
                    todo!()
                }
                EigenLayerSubcommand::CheckOperatorRegistration { rpc, address } => {
                    todo!()
                }
            },
            OperatorsSubcommand::Symbiotic { subcommand } => match subcommand {
                SymbioticSubcommand::RegisterIntoBolt { operator_rpc } => {
                    todo!()
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cli::{Chain, EigenLayerSubcommand, OperatorsCommand, OperatorsSubcommand},
        contracts::{
            deployments_for_chain, eigenlayer::IStrategy, strategy_to_address, EigenLayerStrategy,
        },
    };
    use alloy::{
        primitives::{keccak256, utils::parse_units, Address, B256, U256},
        providers::{ext::AnvilApi, Provider, ProviderBuilder},
        signers::k256::ecdsa::SigningKey,
        sol_types::SolValue,
    };

    #[tokio::test]
    async fn test_deposit_into_strategy() {
        let rpc_url = "https://holesky.drpc.org";
        let provider = ProviderBuilder::new().on_anvil_with_config(|anvil| anvil.fork(rpc_url));
        let anvil_url = provider.client().transport().url();

        let mut rnd = rand::thread_rng();
        let secret_key = SigningKey::random(&mut rnd);
        let account = Address::from_private_key(&secret_key);

        // Add balance to the operator
        provider.anvil_set_balance(account, U256::from(u64::MAX)).await.expect("set balance");

        let deployments = deployments_for_chain(Chain::Holesky);

        let weth_strategy_address = strategy_to_address(
            EigenLayerStrategy::WEth,
            deployments.eigen_layer.supported_strategies,
        );
        let strategy = IStrategy::new(weth_strategy_address, provider.clone());
        let weth_address = strategy.underlyingToken().call().await.expect("underlying token").token;

        // Mock WETH balance using the Anvil API.
        let hashed_slot = keccak256((account, U256::from(3)).abi_encode());
        let mocked_balance: U256 = parse_units("100.0", "ether").expect("parse ether").into();
        provider
            .anvil_set_storage_at(weth_address, hashed_slot.into(), mocked_balance.into())
            .await
            .expect("to set storage");

        let command = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::DepositIntoStrategy {
                    rpc_url: anvil_url.parse().expect("valid url"),
                    operator_private_key: B256::try_from(secret_key.to_bytes().as_slice())
                        .expect("valid secret key"),
                    strategy: EigenLayerStrategy::WEth,
                    amount: parse_units("1.0", "ether").expect("parse ether").into(),
                },
            },
        };

        command.run().await.expect("run command");
    }
}
