use alloy::{
    network::EthereumWallet,
    primitives::{
        utils::{format_ether, Unit},
        Bytes, Uint, U256,
    },
    providers::ProviderBuilder,
    signers::{local::PrivateKeySigner, SignerSync},
    sol_types::SolInterface,
};

use chrono::{Duration, TimeDelta, Utc};

use eyre::Context;
use tracing::{info, warn};

use crate::{
    cli::{Chain, EigenLayerSubcommand},
    common::{
        bolt_manager::BoltManagerContract::{self, BoltManagerContractErrors},
        request_confirmation, try_parse_contract_error,
    },
    contracts::{
        bolt::{
            BoltEigenLayerMiddleware::{self, BoltEigenLayerMiddlewareErrors},
            SignatureWithSaltAndExpiry,
        },
        deployments_for_chain,
        eigenlayer::{
            AVSDirectory, IStrategy::IStrategyInstance, IStrategyManager::IStrategyManagerInstance,
        },
        erc20::IERC20::IERC20Instance,
        strategy_to_address,
    },
};

impl EigenLayerSubcommand {
    /// Run the EigenLayer subcommand.
    pub async fn run(self) -> eyre::Result<()> {
        match self {
            Self::Deposit { rpc_url, strategy, amount, operator_private_key } => {
                let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                    .wrap_err("valid private key")?;
                let operator = signer.address();

                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(EthereumWallet::from(signer))
                    .on_http(rpc_url);

                let chain = Chain::try_from_provider(&provider).await?;

                let deployments = deployments_for_chain(chain);

                let strategy_address =
                    strategy_to_address(strategy, deployments.eigen_layer.supported_strategies);
                let strategy_contract = IStrategyInstance::new(strategy_address, provider.clone());
                let strategy_manager_address = deployments.eigen_layer.strategy_manager;
                let strategy_manager =
                    IStrategyManagerInstance::new(strategy_manager_address, provider.clone());

                let token = strategy_contract.underlyingToken().call().await?.token;

                let amount = amount * Unit::ETHER.wei();

                info!(%strategy, %token, amount = format_ether(amount), ?operator, "Depositing funds into EigenLayer strategy");

                request_confirmation();

                let token_erc20 = IERC20Instance::new(token, provider);

                let balance = token_erc20.balanceOf(operator).call().await?._0;

                info!("Operator token balance: {}", format_ether(balance));

                let result = token_erc20.approve(strategy_manager_address, amount).send().await?;

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

            Self::Register { rpc_url, operator_rpc, salt, operator_private_key } => {
                let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                    .wrap_err("valid private key")?;

                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(EthereumWallet::from(signer.clone()))
                    .on_http(rpc_url);

                let chain = Chain::try_from_provider(&provider).await?;

                info!(operator = %signer.address(), rpc = %operator_rpc, ?chain, "Registering EigenLayer operator");

                request_confirmation();

                let deployments = deployments_for_chain(chain);

                let bolt_avs_address = deployments.bolt.eigenlayer_middleware;
                let bolt_eigenlayer_middleware =
                    BoltEigenLayerMiddleware::new(bolt_avs_address, provider.clone());

                let avs_directory =
                    AVSDirectory::new(deployments.eigen_layer.avs_directory, provider);

                const EXPIRY_DURATION: TimeDelta = Duration::minutes(20);
                let expiry = U256::from((Utc::now() + EXPIRY_DURATION).timestamp());

                let signature_digest_hash = avs_directory
                    .calculateOperatorAVSRegistrationDigestHash(
                        signer.address(),
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

                match bolt_eigenlayer_middleware
                    .registerOperator(operator_rpc.to_string(), signature)
                    .send()
                    .await
                {
                    Ok(pending) => {
                        info!(
                            hash = ?pending.tx_hash(),
                            "registerOperator transaction sent, awaiting receipt..."
                        );

                        let receipt = pending.get_receipt().await?;
                        if !receipt.status() {
                            eyre::bail!("Transaction failed: {:?}", receipt)
                        }

                        info!("Succesfully registered EigenLayer operator");
                    }
                    Err(e) => {
                        match try_parse_contract_error::<BoltEigenLayerMiddlewareErrors>(e)? {
                            BoltEigenLayerMiddlewareErrors::AlreadyRegistered(_) => {
                                eyre::bail!("Operator already registered in bolt")
                            }
                            BoltEigenLayerMiddlewareErrors::NotOperator(_) => {
                                eyre::bail!("Operator not registered in EigenLayer")
                            }
                            BoltEigenLayerMiddlewareErrors::SaltSpent(_) => {
                                eyre::bail!("Salt already spent")
                            }
                            other => unreachable!(
                                "Unexpected error with selector {:?}",
                                other.selector()
                            ),
                        }
                    }
                }

                Ok(())
            }

            Self::Deregister { rpc_url, operator_private_key } => {
                let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                    .wrap_err("valid private key")?;
                let address = signer.address();

                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(EthereumWallet::from(signer))
                    .on_http(rpc_url);

                let chain = Chain::try_from_provider(&provider).await?;

                info!(operator = %address, ?chain, "Deregistering EigenLayer operator");

                request_confirmation();

                let deployments = deployments_for_chain(chain);

                let bolt_avs_address = deployments.bolt.eigenlayer_middleware;
                let bolt_eigenlayer_middleware =
                    BoltEigenLayerMiddleware::new(bolt_avs_address, provider);

                match bolt_eigenlayer_middleware.deregisterOperator().send().await {
                    Ok(pending) => {
                        info!(
                            hash = ?pending.tx_hash(),
                            "deregisterOperator transaction sent, awaiting receipt..."
                        );

                        let receipt = pending.get_receipt().await?;
                        if !receipt.status() {
                            eyre::bail!("Transaction failed: {:?}", receipt)
                        }

                        info!("Succesfully deregistered EigenLayer operator");
                    }
                    Err(e) => {
                        match try_parse_contract_error::<BoltEigenLayerMiddlewareErrors>(e)? {
                            BoltEigenLayerMiddlewareErrors::NotRegistered(_) => {
                                eyre::bail!("Operator not registered in bolt")
                            }
                            other => unreachable!(
                                "Unexpected error with selector {:?}",
                                other.selector()
                            ),
                        }
                    }
                }

                Ok(())
            }

            Self::UpdateRpc { rpc_url, operator_private_key, operator_rpc } => {
                let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                    .wrap_err("valid private key")?;
                let address = signer.address();

                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(EthereumWallet::from(signer))
                    .on_http(rpc_url);

                let chain = Chain::try_from_provider(&provider).await?;

                info!(operator = %address, rpc = %operator_rpc, ?chain, "Updating EigenLayer operator RPC");

                request_confirmation();

                let deployments = deployments_for_chain(chain);

                let bolt_manager =
                    BoltManagerContract::new(deployments.bolt.manager, provider.clone());
                if bolt_manager.isOperator(address).call().await?._0 {
                    info!(?address, "EigenLayer operator is registered");
                } else {
                    warn!(?address, "Operator not registered");
                    return Ok(());
                }

                match bolt_manager.updateOperatorRPC(operator_rpc.to_string()).send().await {
                    Ok(pending) => {
                        info!(
                            hash = ?pending.tx_hash(),
                            "updateOperatorRPC transaction sent, awaiting receipt..."
                        );

                        let receipt = pending.get_receipt().await?;
                        if !receipt.status() {
                            eyre::bail!("Transaction failed: {:?}", receipt)
                        }

                        info!("Succesfully updated EigenLayer operator RPC");
                    }
                    Err(e) => match try_parse_contract_error::<BoltManagerContractErrors>(e)? {
                        BoltManagerContractErrors::OperatorNotRegistered(_) => {
                            eyre::bail!("Operator not registered in bolt")
                        }
                        other => {
                            unreachable!("Unexpected error with selector {:?}", other.selector())
                        }
                    },
                }
                Ok(())
            }

            Self::Status { rpc_url: rpc, address } => {
                let provider = ProviderBuilder::new().on_http(rpc.clone());

                let chain = Chain::try_from_provider(&provider).await?;

                let deployments = deployments_for_chain(chain);
                let bolt_manager =
                    BoltManagerContract::new(deployments.bolt.manager, provider.clone());
                if bolt_manager.isOperator(address).call().await?._0 {
                    info!(?address, "EigenLayer operator is registered");
                } else {
                    warn!(?address, "Operator not registered");
                    return Ok(())
                }

                match bolt_manager.getOperatorData(address).call().await {
                    Ok(operator_data) => {
                        info!(?address, operator_data = ?operator_data._0, "Operator data");
                    }
                    Err(e) => match try_parse_contract_error::<BoltManagerContractErrors>(e)? {
                        BoltManagerContractErrors::KeyNotFound(_) => {
                            warn!(?address, "Operator data not found");
                        }
                        other => {
                            unreachable!("Unexpected error with selector {:?}", other.selector())
                        }
                    },
                }

                // Check if operator has collateral
                let mut total_collateral = Uint::from(0);
                for (name, collateral) in deployments.collateral {
                    let stake =
                        match bolt_manager.getOperatorStake(address, collateral).call().await {
                            Ok(stake) => stake._0,
                            Err(e) => {
                                match try_parse_contract_error::<BoltEigenLayerMiddlewareErrors>(e)?
                                {
                                    BoltEigenLayerMiddlewareErrors::KeyNotFound(_) => Uint::from(0),
                                    other => unreachable!(
                                        "Unexpected error with selector {:?}",
                                        other.selector()
                                    ),
                                }
                            }
                        };
                    if stake > Uint::from(0) {
                        total_collateral += stake;
                        info!(?address, token = %name, amount = ?stake, "Operator has collateral");
                    }
                }
                if total_collateral >= Unit::ETHER.wei() {
                    info!(?address, total_collateral=?total_collateral, "Operator is active");
                } else if total_collateral > Uint::from(0) {
                    info!(?address, total_collateral=?total_collateral, "Total operator collateral");
                } else {
                    warn!(?address, "Operator has no collateral");
                }

                Ok(())
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
            eigenlayer::{DelegationManager, IStrategy},
            strategy_to_address, EigenLayerStrategy,
        },
    };
    use alloy::{
        network::EthereumWallet,
        node_bindings::Anvil,
        primitives::{keccak256, utils::parse_units, Address, B256, U256},
        providers::{ext::AnvilApi, Provider, ProviderBuilder, WalletProvider},
        signers::local::PrivateKeySigner,
        sol_types::SolValue,
    };
    use alloy_node_bindings::WEI_IN_ETHER;

    #[tokio::test]
    async fn test_eigenlayer_flow() {
        let _ = tracing_subscriber::fmt::try_init();
        let s1 = PrivateKeySigner::random();
        let secret_key = s1.to_bytes();

        let wallet = EthereumWallet::new(s1);

        let rpc_url = "https://holesky.drpc.org";
        let anvil = Anvil::default().fork(rpc_url).spawn();
        let anvil_url = anvil.endpoint_url();
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(anvil_url.clone());

        let account = provider.default_signer_address();

        // Add balance to the operator
        provider.anvil_set_balance(account, WEI_IN_ETHER).await.expect("set balance");

        let balance = provider.get_balance(account).await.expect("failed getting balance");
        println!("Signer balance: {balance:?}");

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

        // 1. Register the operator into EigenLayer. This should be done by the operator using the
        //    EigenLayer CLI, but we do it here for testing purposes.

        let delegation_manager =
            DelegationManager::new(deployments.eigen_layer.delegation_manager, provider.clone());

        let receipt = delegation_manager
            .registerAsOperator(Address::ZERO, 0, "https://bolt.chainbound.io/rpc".to_string())
            .send()
            .await
            .expect("to send register as operator")
            .get_receipt()
            .await
            .expect("to get receipt for register as operator");

        assert!(receipt.status(), "operator should be registered");
        // println!("Registered operator with address {}", account);

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
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                    strategy: EigenLayerStrategy::WEth,
                    amount: U256::from(1),
                },
            },
        };

        deposit_into_strategy.run().await.expect("to deposit into strategy");

        // 3. Register the operator into Bolt AVS

        let register_operator = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::Register {
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                    operator_rpc: "https://bolt.chainbound.io/rpc".parse().expect("valid url"),
                    salt: B256::ZERO,
                },
            },
        };

        register_operator.run().await.expect("to register operator");

        // 4. Check operator registration
        let check_operator_registration = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::Status {
                    rpc_url: anvil_url.clone(),
                    address: account,
                },
            },
        };

        check_operator_registration.run().await.expect("to check operator registration");

        let update_rpc = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::UpdateRpc {
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                    operator_rpc: "https://boooooolt.chainbound.io/rpc".parse().expect("valid url"),
                },
            },
        };

        update_rpc.run().await.expect("to update operator rpc");

        let check_operator_registration = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::Status {
                    rpc_url: anvil_url.clone(),
                    address: account,
                },
            },
        };

        check_operator_registration.run().await.expect("to check operator registration");

        let deregister_operator = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::Deregister {
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                },
            },
        };

        deregister_operator.run().await.expect("to deregister operator");

        let check_operator_registration = OperatorsCommand {
            subcommand: OperatorsSubcommand::EigenLayer {
                subcommand: EigenLayerSubcommand::Status { rpc_url: anvil_url, address: account },
            },
        };

        check_operator_registration.run().await.expect("to check operator registration");
    }
}
