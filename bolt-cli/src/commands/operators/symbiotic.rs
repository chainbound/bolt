use alloy::{
    network::EthereumWallet,
    primitives::{utils::Unit, Uint},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol_types::SolInterface,
};
use eyre::Context;
use tracing::{info, warn};

use crate::{
    cli::{Chain, SymbioticSubcommand},
    common::{
        bolt_manager::BoltManagerContract::{self, BoltManagerContractErrors},
        request_confirmation, try_parse_contract_error,
    },
    contracts::{
        bolt::BoltSymbioticMiddleware::{self, BoltSymbioticMiddlewareErrors},
        deployments_for_chain,
        symbiotic::IOptInService,
    },
};

impl SymbioticSubcommand {
    /// Run the symbiotic subcommand.
    pub async fn run(self) -> eyre::Result<()> {
        match self {
            Self::Register { operator_rpc, operator_private_key, rpc_url } => {
                let signer = PrivateKeySigner::from_bytes(&operator_private_key)
                    .wrap_err("valid private key")?;

                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(EthereumWallet::from(signer.clone()))
                    .on_http(rpc_url);

                let chain = Chain::try_from_provider(&provider).await?;

                let deployments = deployments_for_chain(chain);

                info!(operator = %signer.address(), rpc = %operator_rpc, ?chain, "Registering Symbiotic operator");

                request_confirmation();

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

                match middleware.registerOperator(operator_rpc.to_string()).send().await {
                    Ok(pending) => {
                        info!(
                            hash = ?pending.tx_hash(),
                            "registerOperator transaction sent, awaiting receipt..."
                        );

                        let receipt = pending.get_receipt().await?;
                        if !receipt.status() {
                            eyre::bail!("Transaction failed: {:?}", receipt)
                        }

                        info!("Succesfully registered Symbiotic operator");
                    }
                    Err(e) => match try_parse_contract_error::<BoltSymbioticMiddlewareErrors>(e)? {
                        BoltSymbioticMiddlewareErrors::AlreadyRegistered(_) => {
                            eyre::bail!("Operator already registered in bolt")
                        }
                        BoltSymbioticMiddlewareErrors::NotOperator(_) => {
                            eyre::bail!("Operator not registered in Symbiotic")
                        }
                        other => {
                            unreachable!("Unexpected error with selector {:?}", other.selector())
                        }
                    },
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

                let deployments = deployments_for_chain(chain);

                info!(operator = %address, ?chain, "Deregistering Symbiotic operator");

                request_confirmation();

                let middleware =
                    BoltSymbioticMiddleware::new(deployments.bolt.symbiotic_middleware, provider);

                match middleware.deregisterOperator().send().await {
                    Ok(pending) => {
                        info!(
                            hash = ?pending.tx_hash(),
                            "deregisterOperator transaction sent, awaiting receipt..."
                        );

                        let receipt = pending.get_receipt().await?;
                        if !receipt.status() {
                            eyre::bail!("Transaction failed: {:?}", receipt)
                        }

                        info!("Succesfully deregistered Symbiotic operator");
                    }
                    Err(e) => match try_parse_contract_error::<BoltSymbioticMiddlewareErrors>(e)? {
                        BoltSymbioticMiddlewareErrors::NotRegistered(_) => {
                            eyre::bail!("Operator not registered in bolt")
                        }
                        other => {
                            unreachable!("Unexpected error with selector {:?}", other.selector())
                        }
                    },
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

                info!(operator = %address, rpc = %operator_rpc, ?chain, "Updating Symbiotic operator RPC");

                request_confirmation();

                let deployments = deployments_for_chain(chain);

                let bolt_manager =
                    BoltManagerContract::new(deployments.bolt.manager, provider.clone());
                if bolt_manager.isOperator(address).call().await?._0 {
                    info!(?address, "Symbiotic operator is registered");
                } else {
                    warn!(?address, "Operator not registered");
                    return Ok(())
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

                        info!("Succesfully updated Symbiotic operator RPC");
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

            Self::Status { rpc_url, address } => {
                let provider = ProviderBuilder::new().on_http(rpc_url.clone());

                let chain = Chain::try_from_provider(&provider).await?;

                let deployments = deployments_for_chain(chain);
                let bolt_manager =
                    BoltManagerContract::new(deployments.bolt.manager, provider.clone());
                if bolt_manager.isOperator(address).call().await?._0 {
                    info!(?address, "Symbiotic operator is registered");
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
                                match try_parse_contract_error::<BoltSymbioticMiddlewareErrors>(e)?
                                {
                                    BoltSymbioticMiddlewareErrors::KeyNotFound(_) => Uint::from(0),
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
        cli::{Chain, OperatorsCommand, OperatorsSubcommand, SymbioticSubcommand},
        contracts::deployments_for_chain,
    };
    use alloy::{
        network::EthereumWallet,
        node_bindings::Anvil,
        primitives::{address, keccak256, utils::parse_units, U256},
        providers::{ext::AnvilApi, ProviderBuilder, WalletProvider},
        signers::local::PrivateKeySigner,
        sol_types::SolValue,
    };
    use reqwest::Url;
    use std::process::{Command, Output};

    /// Ignored since it requires Symbiotic CLI: https://docs.symbiotic.fi/guides/cli/#installation
    /// To run this test, install the CLI, and then move the binary in the `symbiotic-cli` directory
    /// which is git-ignored for this purpose.
    #[tokio::test]
    #[ignore = "requires Symbiotic CLI installed"]
    async fn test_symbiotic_flow() {
        let s1 = PrivateKeySigner::random();
        let secret_key = s1.to_bytes();
        let wallet = EthereumWallet::new(s1);

        let rpc_url = "https://holesky.drpc.org";
        let anvil = Anvil::default().fork(rpc_url).spawn();
        let anvil_url = Url::parse(&anvil.endpoint()).expect("valid URL");
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(anvil_url.clone());

        let account = provider.default_signer_address();

        // Add balance to the operator
        provider.anvil_set_balance(account, U256::from(u64::MAX)).await.expect("set balance");

        let deployments = deployments_for_chain(Chain::Holesky);

        let weth_address = address!("94373a4919B3240D86eA41593D5eBa789FEF3848");

        // Mock WETH balance using the Anvil API.
        let hashed_slot = keccak256((account, U256::from(3)).abi_encode());
        let mocked_balance: U256 = parse_units("100.0", "ether").expect("parse ether").into();
        provider
            .anvil_set_storage_at(weth_address, hashed_slot.into(), mocked_balance.into())
            .await
            .expect("to set storage");

        let print_output = |output: Output| {
            println!("{}", String::from_utf8_lossy(&output.stdout));
        };

        // We now follow the steps described in the Holesky guide

        let register_operator = Command::new("python3")
            .arg("symbiotic-cli/symb.py")
            .arg("--chain")
            .arg("holesky")
            .arg("--provider")
            .arg(anvil_url.to_string())
            .arg("register-operator")
            .arg("--private-key")
            .arg(secret_key.to_string())
            .output()
            .expect("to register operator");

        print_output(register_operator);

        let opt_in_network = Command::new("python3")
            .arg("symbiotic-cli/symb.py")
            .arg("--chain")
            .arg("holesky")
            .arg("--provider")
            .arg(anvil_url.to_string())
            .arg("opt-in-network")
            .arg("--private-key")
            .arg(secret_key.to_string())
            .arg(deployments.symbiotic.network.to_string())
            .output()
            .expect("to opt-in-network");

        print_output(opt_in_network);

        let vault = deployments.symbiotic.supported_vaults[3]; // WETH vault

        let opt_in_vault = Command::new("python3")
            .arg("symbiotic-cli/symb.py")
            .arg("--chain")
            .arg("holesky")
            .arg("--provider")
            .arg(anvil_url.to_string())
            .arg("opt-in-vault")
            .arg("--private-key")
            .arg(secret_key.to_string())
            .arg(vault.to_string())
            .output()
            .expect("to opt-in-vault");

        print_output(opt_in_vault);

        let deposit = Command::new("python3")
            .arg("symbiotic-cli/symb.py")
            .arg("--chain")
            .arg("holesky")
            .arg("--provider")
            .arg(anvil_url.to_string())
            .arg("deposit")
            .arg("--private-key")
            .arg(secret_key.to_string())
            .arg(vault.to_string())
            .arg("1") // 1 ether
            .output()
            .expect("to opt-in-vault");

        print_output(deposit);

        let register_into_bolt = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Register {
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                    operator_rpc: "https://bolt.chainbound.io".parse().expect("valid url"),
                },
            },
        };

        register_into_bolt.run().await.expect("to register into bolt");

        let check_status = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Status {
                    rpc_url: anvil_url.clone(),
                    address: account,
                },
            },
        };

        check_status.run().await.expect("to check operator status");

        let update_rpc = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::UpdateRpc {
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                    operator_rpc: "https://boooooooooooooooolt.chainbound.io"
                        .parse()
                        .expect("valid url"),
                },
            },
        };

        update_rpc.run().await.expect("to update operator rpc");

        let check_status = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Status {
                    rpc_url: anvil_url.clone(),
                    address: account,
                },
            },
        };

        check_status.run().await.expect("to check operator status");

        let deregister_command = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Deregister {
                    rpc_url: anvil_url.clone(),
                    operator_private_key: secret_key,
                },
            },
        };

        deregister_command.run().await.expect("to deregister operator");

        let check_status = OperatorsCommand {
            subcommand: OperatorsSubcommand::Symbiotic {
                subcommand: SymbioticSubcommand::Status { rpc_url: anvil_url, address: account },
            },
        };

        check_status.run().await.expect("to check operator status");
    }
}
