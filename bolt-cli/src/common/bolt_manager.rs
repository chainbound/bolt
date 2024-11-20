#![allow(dead_code)] // TODO: rm this

use std::str::FromStr;

use alloy::{
    contract::{Error as ContractError, Result as ContractResult},
    primitives::{Address, Bytes, B256},
    providers::{ProviderBuilder, RootProvider},
    sol,
    sol_types::{Error as SolError, SolInterface},
    transports::{http::Http, TransportError},
};
use reqwest::{Client, Url};
use serde::Serialize;

use BoltManagerContract::{BoltManagerContractErrors, BoltManagerContractInstance, ProposerStatus};

/// Bolt Manager contract bindings.
#[derive(Debug, Clone)]
pub struct BoltManager(BoltManagerContractInstance<Http<Client>, RootProvider<Http<Client>>>);

impl BoltManager {
    /// Creates a new BoltManager instance.
    pub fn new<U: Into<Url>>(execution_client_url: U, manager_address: Address) -> Self {
        let provider = ProviderBuilder::new().on_http(execution_client_url.into());
        let manager = BoltManagerContract::new(manager_address, provider);

        Self(manager)
    }

    /// Gets the sidecar RPC URL for a given validator index.
    ///
    /// Returns Ok(None) if the operator is not found in the registry.
    pub async fn get_sidecar_rpc_url_for_validator(
        &self,
        pubkey_hash: B256,
    ) -> ContractResult<Option<String>> {
        let registrant = self.get_proposer_status(pubkey_hash).await?;
        Ok(registrant.and_then(|r| if r.active { Some(r.operatorRPC) } else { None }))
    }

    /// Gets the proposer status for a given pubkeyhash.
    ///
    /// Returns Ok(None) if the proposer is not found in the registry.
    pub async fn get_proposer_status(
        &self,
        pubkey_hash: B256,
    ) -> ContractResult<Option<ProposerStatus>> {
        let returndata = self.0.getProposerStatus(pubkey_hash).call().await;

        // TODO: clean this after https://github.com/alloy-rs/alloy/issues/787 is merged
        let error = match returndata.map(|data| data._0) {
            Ok(proposer) => return Ok(Some(proposer)),
            Err(error) => match error {
                ContractError::TransportError(TransportError::ErrorResp(err)) => {
                    let data = err.data.unwrap_or_default();
                    let data = data.get().trim_matches('"');
                    let data = Bytes::from_str(data).unwrap_or_default();

                    BoltManagerContractErrors::abi_decode(&data, true)?
                }
                e => return Err(e),
            },
        };

        if matches!(error, BoltManagerContractErrors::ValidatorDoesNotExist(_)) {
            Ok(None)
        } else {
            Err(SolError::custom(format!(
                "unexpected Solidity error selector: {:?}",
                error.selector()
            ))
            .into())
        }
    }
}

sol! {
    #[sol(rpc)]
    interface BoltManagerContract {
        #[derive(Debug, Default, Serialize)]
        struct ProposerStatus {
            bytes32 pubkeyHash;
            bool active;
            address operator;
            string operatorRPC;
            address[] collaterals;
            uint256[] amounts;
        }

        function getProposerStatus(bytes32 pubkeyHash) external view returns (ProposerStatus memory);

        function isOperator(address operator) public view returns (bool);

        error InvalidQuery();
        error ValidatorDoesNotExist();
    }
}
