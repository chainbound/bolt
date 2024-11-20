use std::io::Write;

use alloy::{
    network::EthereumWallet,
    primitives::{utils::format_ether, Bytes},
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::{local::PrivateKeySigner, SignerSync},
};
use eyre::Context;
use tracing::{info, warn};

use crate::{
    cli::{
        Chain, EigenLayerSubcommand, OperatorsCommand, OperatorsSubcommand, SymbioticSubcommand,
    },
    common::bolt_manager::BoltManagerContract,
    contracts::{
        bolt::{
            BoltEigenLayerMiddleware,
            BoltSymbioticMiddleware::{self},
            SignatureWithSaltAndExpiry,
        },
        deployments_for_chain,
        eigenlayer::{
            AVSDirectory, IStrategy::IStrategyInstance, IStrategyManager::IStrategyManagerInstance,
        },
        erc20::IERC20::IERC20Instance,
        strategy_to_address,
        symbiotic::IOptInService,
    },
};

impl OperatorsCommand {
    pub async fn run(self) -> eyre::Result<()> {
        match self.subcommand {
            OperatorsSubcommand::EigenLayer { subcommand } => match subcommand {
                EigenLayerSubcommand::Deposit {
                    rpc_url,
                    strategy,
                    amount,
                    operator_private_key,
                } => {
                    let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                        .wrap_err("valid private key")?;
                    let operator = signer.address();

                    let provider = ProviderBuilder::new()
                        .with_recommended_fillers()
                        .wallet(EthereumWallet::from(signer))
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

                    info!(%strategy, %token, amount = format_ether(amount), ?operator, "Depositing funds into EigenLayer strategy");

                    if !request_confirmation() {
                        info!("Aborting");
                        return Ok(());
                    }

                    let token_erc20 = IERC20Instance::new(token, provider.clone());

                    let balance = token_erc20
                        .balanceOf(provider.clone().default_signer_address())
                        .call()
                        .await?
                        ._0;

                    info!("Operator token balance: {}", format_ether(balance));

                    let result =
                        token_erc20.approve(strategy_manager_address, amount).send().await?;

                    info!(hash = ?result.tx_hash(), "Approving transfer of {} {:?}, awaiting receipt...", amount, strategy);
                    let result = result.watch().await?;
                    info!("Approval transaction included. Transaction hash: {:?}", result);

                    let result = strategy_manager
                        .depositIntoStrategy(strategy_address, token, amount)
                        .send()
                        .await?;

                    info!(hash = ?result.tx_hash(), "Submitted deposit transaction, awaiting receipt...");
                    let receipt = result.get_receipt().await?;

                    if !receipt.status() {
                        eyre::bail!("Transaction failed: {:?}", receipt)
                    }

                    info!("Succesfully deposited collateral into strategy");

                    Ok(())
                }
                EigenLayerSubcommand::Register {
                    rpc_url,
                    operator_rpc,
                    salt,
                    expiry,
                    operator_private_key,
                } => {
                    let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                        .wrap_err("valid private key")?;

                    let provider = ProviderBuilder::new()
                        .with_recommended_fillers()
                        .wallet(EthereumWallet::from(signer.clone()))
                        .on_http(rpc_url.clone());

                    let chain_id = provider.get_chain_id().await?;
                    let chain = Chain::from_id(chain_id)
                        .unwrap_or_else(|| panic!("chain id {} not supported", chain_id));

                    info!(operator = %signer.address(), rpc = %operator_rpc, ?chain, "Registering EigenLayer operator");

                    if !request_confirmation() {
                        info!("Aborting");
                        return Ok(());
                    }

                    let deployments = deployments_for_chain(chain);

                    let bolt_avs_address = deployments.bolt.eigenlayer_middleware;
                    let bolt_eigenlayer_middleware =
                        BoltEigenLayerMiddleware::new(bolt_avs_address, provider.clone());

                    let avs_directory =
                        AVSDirectory::new(deployments.eigen_layer.avs_directory, provider.clone());
                    let signature_digest_hash = avs_directory
                        .calculateOperatorAVSRegistrationDigestHash(
                            provider.clone().default_signer_address(),
                            bolt_avs_address,
                            salt,
                            expiry,
                        )
                        .call()
                        .await?
                        ._0;

                    let signature =
                        Bytes::from(signer.sign_hash_sync(&signature_digest_hash)?.as_bytes());
                    let signature = SignatureWithSaltAndExpiry { signature, expiry, salt };

                    let result = bolt_eigenlayer_middleware
                        .registerOperator(operator_rpc.to_string(), signature)
                        .send()
                        .await?;

                    info!(
                        hash = ?result.tx_hash(),
                        "registerOperator transaction sent, awaiting receipt..."
                    );

                    let receipt = result.get_receipt().await?;
                    if !receipt.status() {
                        eyre::bail!("Transaction failed: {:?}", receipt)
                    }

                    info!("Succesfully registered Symbiotic operator");

                    Ok(())
                }
                EigenLayerSubcommand::Status { rpc_url: rpc, address } => {
                    if !request_confirmation() {
                        return Ok(());
                    }

                    let provider = ProviderBuilder::new().on_http(rpc.clone());
                    let chain_id = provider.get_chain_id().await?;
                    let chain = Chain::from_id(chain_id)
                        .unwrap_or_else(|| panic!("chain id {} not supported", chain_id));

                    let deployments = deployments_for_chain(chain);
                    let bolt_manager =
                        BoltManagerContract::new(deployments.bolt.manager, provider.clone());
                    if bolt_manager.isOperator(address).call().await?._0 {
                        info!(?address, "EigenLayer operator is registered");
                    } else {
                        warn!(?address, "Operator not registered");
                    }

                    Ok(())
                }
            },
            OperatorsSubcommand::Symbiotic { subcommand } => match subcommand {
                SymbioticSubcommand::Register { operator_rpc, operator_private_key, rpc_url } => {
                    let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                        .wrap_err("valid private key")?;

                    let provider = ProviderBuilder::new()
                        .with_recommended_fillers()
                        .wallet(EthereumWallet::from(signer.clone()))
                        .on_http(rpc_url);

                    let chain_id = provider.get_chain_id().await?;
                    let chain = Chain::from_id(chain_id)
                        .unwrap_or_else(|| panic!("chain id {} not supported", chain_id));

                    let deployments = deployments_for_chain(chain);

                    info!(operator = %signer.address(), rpc = %operator_rpc, ?chain, "Registering Symbiotic operator");

                    if !request_confirmation() {
                        info!("Aborting");
                        return Ok(());
                    }

                    // Check if operator is opted in to the bolt network
                    if !IOptInService::new(
                        deployments.symbiotic.network_opt_in_service,
                        provider.clone(),
                    )
                    .isOptedIn(signer.address(), deployments.symbiotic.network)
                    .call()
                    .await?
                    ._0
                    {
                        eyre::bail!(
                            "Operator with address {} not opted in to the bolt network ({})",
                            signer.address(),
                            deployments.symbiotic.network
                        );
                    }

                    let middleware = BoltSymbioticMiddleware::new(
                        deployments.bolt.symbiotic_middleware,
                        provider.clone(),
                    );

                    let pending =
                        middleware.registerOperator(operator_rpc.to_string()).send().await?;

                    info!(
                        hash = ?pending.tx_hash(),
                        "registerOperator transaction sent, awaiting receipt..."
                    );

                    let receipt = pending.get_receipt().await?;
                    if !receipt.status() {
                        eyre::bail!("Transaction failed: {:?}", receipt)
                    }

                    info!("Succesfully registered Symbiotic operator");

                    Ok(())
                }
                SymbioticSubcommand::Status { rpc_url, address } => {
                    let provider = ProviderBuilder::new().on_http(rpc_url.clone());
                    let chain_id = provider.get_chain_id().await?;
                    let chain = Chain::from_id(chain_id)
                        .unwrap_or_else(|| panic!("chain id {} not supported", chain_id));

                    let deployments = deployments_for_chain(chain);
                    let bolt_manager =
                        BoltManagerContract::new(deployments.bolt.manager, provider.clone());
                    if bolt_manager.isOperator(address).call().await?._0 {
                        info!(?address, "Symbiotic operator is registered");
                    } else {
                        warn!(?address, "Operator not registered");
                    }

                    Ok(())
                }
            },
        }
    }
}

fn request_confirmation() -> bool {
    loop {
        info!("Do you want to continue? (yes/no): ");

        print!("Answer: ");
        std::io::stdout().flush().expect("Failed to flush");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Failed to read input");

        let input = input.trim().to_lowercase();

        match input.as_str() {
            "yes" | "y" => {
                return true;
            }
            "no" | "n" => {
                return false;
            }
            _ => {
                println!("Invalid input. Please type 'yes' or 'no'.");
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        cli::{Chain, EigenLayerSubcommand, OperatorsCommand, OperatorsSubcommand},
        contracts::{
            deployments_for_chain,
            eigenlayer::{DelegationManager, IStrategy, OperatorDetails},
            strategy_to_address, EigenLayerStrategy,
        },
    };
    use alloy::{
        network::EthereumWallet,
        primitives::{keccak256, utils::parse_units, Address, B256, U256},
        providers::{ext::AnvilApi, Provider, ProviderBuilder, WalletProvider},
        signers::local::PrivateKeySigner,
        sol_types::SolValue,
    };
    use rand::Rng;

    #[tokio::test]
    async fn test_eigenlayer_flow() {
        let mut rnd = rand::thread_rng();
        let secret_key = B256::from(rnd.gen::<[u8; 32]>());
        let wallet = PrivateKeySigner::from_bytes(&secret_key).expect("valid private key");

        let rpc_url = "https://holesky.drpc.org";
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::from(wallet))
            .on_anvil_with_config(|anvil| anvil.fork(rpc_url));
        let anvil_url = provider.client().transport().url();

        let account = provider.default_signer_address();

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

        let random_address = Address::from(rnd.gen::<[u8; 20]>());

        // 1. Register the operator into EigenLayer. This should be done by the operator using the
        //    EigenLayer CLI, but we do it here for testing purposes.

        let delegation_manager =
            DelegationManager::new(deployments.eigen_layer.delegation_manager, provider.clone());
        let receipt = delegation_manager
            .registerAsOperator(
                OperatorDetails {
                    earningsReceiver: random_address,
                    delegationApprover: Address::ZERO,
                    stakerOptOutWindowBlocks: 32,
                },
                "https://bolt.chainbound.io/rpc".to_string(),
            )
            .send()
            .await
            .expect("to send register as operator")
            .get_receipt()
            .await
            .expect("to get receipt for register as operator");

        assert!(receipt.status(), "operator should be registered");
        println!("Registered operator with address {}", account);

        let is_operator = delegation_manager
            .isOperator(account)
            .call()
            .await
            .expect("to check if operator is registered")
            ._0;
        println!("is operator {}", is_operator);

        // 2. Deposit into the strategy

        let deposit_into_strategy = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::Deposit {
                    rpc_url: anvil_url.parse().expect("valid url"),
                    operator_private_key: secret_key,
                    strategy: EigenLayerStrategy::WEth,
                    amount: parse_units("1.0", "ether").expect("parse ether").into(),
                },
            },
        };

        deposit_into_strategy.run().await.expect("to deposit into strategy");

        // 3. Register the operator into Bolt AVS

        let register_operator = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::Register {
                    rpc_url: anvil_url.parse().expect("valid url"),
                    operator_private_key: secret_key,
                    operator_rpc: "https://bolt.chainbound.io/rpc".parse().expect("valid url"),
                    salt: B256::ZERO,
                    expiry: U256::MAX,
                },
            },
        };

        register_operator.run().await.expect("to register operator");

        // 4. Check operator registration
        let check_operator_registration = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::Status {
                    rpc_url: anvil_url.parse().expect("valid url"),
                    address: account,
                },
            },
        };

        check_operator_registration.run().await.expect("to check operator registration");
    }
}
