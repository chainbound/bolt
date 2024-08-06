use std::str::FromStr;

use alloy::{
    contract::{Error as ContractError, Result as ContractResult},
    primitives::{Address, Bytes},
    providers::{ProviderBuilder, RootProvider},
    sol,
    sol_types::{Error as SolError, SolInterface},
    transports::{http::Http, TransportError},
};
use beacon_api_client::ProposerDuty;
use reqwest::Client;
use tracing::info;
use url::Url;
use BoltRegistryContract::{BoltRegistryContractErrors, BoltRegistryContractInstance, Registrant};

#[derive(Debug, Clone)]
pub struct BoltRegistry(BoltRegistryContractInstance<Http<Client>, RootProvider<Http<Client>>>);

impl BoltRegistry {
    pub fn new<U: Into<Url>>(execution_client_url: U, registry_address: Address) -> Self {
        let provider = ProviderBuilder::new().on_http(execution_client_url.into());
        let registry = BoltRegistryContract::new(registry_address, provider);

        Self(registry)
    }

    /// Gets the sidecar RPC URL for a given validator index.
    ///
    /// Returns Ok(None) if the operator is not found in the registry.
    #[allow(unused)]
    pub async fn get_sidecar_rpc_url_for_validator(
        &self,
        validator_index: u64,
    ) -> ContractResult<Option<String>> {
        let registrant = self.get_registrant_for_validator(validator_index).await?;
        Ok(registrant.map(|r| r.metadata.rpc))
    }

    /// Gets the operator for a given validator index.
    ///
    /// Returns Ok(None) if the operator is not found in the registry.
    pub async fn get_registrant_for_validator(
        &self,
        validator_index: u64,
    ) -> ContractResult<Option<Registrant>> {
        let returndata = self.0.getOperatorForValidator(validator_index).call().await;

        // TODO: clean this after https://github.com/alloy-rs/alloy/issues/787 is merged
        let error = match returndata.map(|data| data._0) {
            Ok(registrant) => return Ok(Some(registrant)),
            Err(error) => match error {
                ContractError::TransportError(TransportError::ErrorResp(err)) => {
                    let data = err.data.unwrap_or_default();
                    let data = data.get().trim_matches('"');
                    let data = Bytes::from_str(data).unwrap_or_default();

                    BoltRegistryContractErrors::abi_decode(&data, true)?
                }
                e => return Err(e),
            },
        };

        if matches!(error, BoltRegistryContractErrors::NotFound(_)) {
            Ok(None)
        } else {
            Err(SolError::custom(format!(
                "unexpected Solidity error selector: {:?}",
                error.selector()
            ))
            .into())
        }
    }

    /// Gets the next pre-confirmation slot and proposer RPC URL from the registry contract
    ///
    /// Returns Ok(None) if no registered validators are found in the lookahead
    pub async fn next_preconfer_from_registry(
        &self,
        proposer_duties: Vec<ProposerDuty>,
    ) -> ContractResult<Option<(String, u64)>> {
        let mut next_preconfer_slot = 0;
        let mut proposer_rpc = String::new();

        for duty in proposer_duties {
            let res = self.get_registrant_for_validator(duty.validator_index as u64).await;
            match res {
                Ok(Some(token_raw)) => {
                    next_preconfer_slot = duty.slot;
                    proposer_rpc = token_raw.metadata.rpc;
                    info!(
                        "pre-confirmation will be sent for slot {} to validator with index {} at url {}",
                        duty.slot,
                        duty.validator_index,
                        proposer_rpc,
                    );
                    break;
                }
                Ok(None) => {
                    // Handle the case where the result is Ok but contains None.
                    // You might want to continue to the next iteration, log something, or handle it
                    // in another way.
                    info!("No registrant found for validator index {}", duty.validator_index);
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        if next_preconfer_slot == 0 {
            return Ok(None);
        };

        Ok(Some((proposer_rpc, next_preconfer_slot)))
    }
}

sol! {
    #[sol(rpc)]
    interface BoltRegistryContract {
        #[derive(Debug, Default)]
        struct Registrant {
            address operator;
            uint64[] validatorIndexes;
            uint256 enteredAt;
            uint256 exitInitiatedAt;
            uint256 balance;
            Status status;
            MetaData metadata;
        }

        #[derive(Debug, Default)]
        enum Status {
            #[default]
            INACTIVE,
            ACTIVE,
            FROZEN,
            EXITING
        }

        #[derive(Debug, Default)]
        struct MetaData {
            string rpc;
            bytes extra;
        }

        function getOperatorForValidator(uint64 _validatorIndex) external view returns (Registrant memory);

        error NotFound();
        error Unauthorized();
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy::{primitives::U256, sol_types::SolCall};
    use beacon_api_client::ProposerDuty;
    use BoltRegistryContract::{MetaData, Status};

    use super::*;

    #[test]
    fn test_abigen() {
        assert_eq!(BoltRegistryContract::getOperatorForValidatorCall::SELECTOR, [238, 124, 139, 77])
    }

    #[tokio::test]
    async fn test_get_operators_helder() -> eyre::Result<()> {
        let registry = BoltRegistry::new(
            Url::parse("http://remotebeast:4485")?,
            Address::from_str("0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9")?,
        );

        let registrant = registry.get_registrant_for_validator(0).await;
        assert!(matches!(registrant, Ok(None)));

        let registrant = match registry.get_registrant_for_validator(2150).await {
            Ok(Some(registrant)) => registrant,
            e => panic!("unexpected error reading from registry: {:?}", e),
        };

        let expected = Registrant {
            operator: Address::from_str("0xad3cd1b81c80f4a495d6552ae6423508492a27f8")?,
            validatorIndexes: (2145..2245).collect(),
            enteredAt: U256::from(1720183620),
            exitInitiatedAt: U256::from(0),
            balance: U256::from(10000000000000000000u128),
            status: Status::ACTIVE,
            metadata: MetaData {
                rpc: "http://135.181.191.125:8000".to_string(),
                extra: Bytes::from_str("0x")?,
            },
        };

        assert_eq!(registrant.metadata.rpc, expected.metadata.rpc);
        assert_eq!(registrant.metadata.extra, expected.metadata.extra);
        assert_eq!(registrant.operator, expected.operator);
        assert_eq!(registrant.validatorIndexes, expected.validatorIndexes);
        assert_eq!(registrant.enteredAt, expected.enteredAt);
        assert_eq!(registrant.exitInitiatedAt, expected.exitInitiatedAt);
        assert_eq!(registrant.balance, expected.balance);

        Ok(())
    }

    #[tokio::test]
    async fn test_next_preconfer_from_registry() -> eyre::Result<()> {
        let registry = BoltRegistry::new(
            Url::parse("http://remotebeast:4485")?,
            Address::from_str("0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9")?,
        );

        // Mock proposer duties
        let proposer_duties = vec![
            ProposerDuty { public_key: Default::default(), validator_index: 2145, slot: 12345 },
            ProposerDuty { public_key: Default::default(), validator_index: 2150, slot: 12346 },
        ];

        // Calling the next_preconfer_from_registry function
        let result = registry.next_preconfer_from_registry(proposer_duties).await?;

        // Expected result
        let expected_rpc = "http://135.181.191.125:8000".to_string();
        let expected_slot = 12345;

        // Asserting the result
        match result {
            Some((rpc, slot)) => {
                assert_eq!(rpc, expected_rpc);
                assert_eq!(slot, expected_slot);
            }
            None => panic!("Expected some value but got None"),
        }

        Ok(())
    }
}
