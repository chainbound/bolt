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
use alloy::providers::{Provider, ProviderBuilder};

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
                    let strategy = IStrategyInstance::new(strategy_address, provider.clone());
                    let strategy_manager_address = deployments.eigen_layer.strategy_manager;
                    let strategy_manager =
                        IStrategyManagerInstance::new(strategy_manager_address, provider.clone());

                    let token = strategy.underlyingToken().call().await?.token;

                    let token_erc20 = IERC20Instance::new(token, provider);
                    let success =
                        token_erc20.approve(strategy_manager_address, amount).call().await?._0;
                    if !success {
                        panic!("Failed to approve token transfer");
                    }

                    let shares = strategy_manager
                        .depositIntoStrategy(strategy_address, token, amount)
                        .call()
                        .await?
                        .shares;

                    println!(
                        "Deposited {} tokens into strategy, received {} shares",
                        amount, shares
                    );
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
        todo!();
    }
}
