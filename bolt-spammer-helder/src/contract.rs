// use ethers::{
//     abi::{Abi, Token},
//     contract::{Contract, ContractError},
//     providers::{Http, Provider},
//     types::Address,
// };
// use eyre::{eyre, Result};
// use std::{path::PathBuf, sync::Arc};

// use beacon_api_client::ProposerDuty;

// /// Returns the next pre-confirmation slot and proposer RPC URL from the registry contract
// ///
// /// Fails if no registered validators are found in the lookahead
// pub async fn next_preconfer_from_registry(
//     proposer_duties: Vec<ProposerDuty>,
//     abi_path: PathBuf,
//     registry_address: Address,
//     eth_provider: Arc<Provider<Http>>,
// ) -> Result<(String, u64)> {
//     let contract_abi: Abi = serde_json::from_str(&std::fs::read_to_string(abi_path)?)?;
//     let registry_contract = Contract::new(registry_address, contract_abi, eth_provider);
//     let mut next_preconfer_slot = 0;
//     let mut proposer_rpc = String::new();
//     for duty in proposer_duties {
//         let res = registry_contract
//             .method::<u64, Token>("getOperatorForValidator", duty.validator_index as u64)?
//             .call()
//             .await;
//         match res {
//             Ok(token_raw) => {
//                 next_preconfer_slot = duty.slot;
//                 proposer_rpc = try_parse_url_from_token(token_raw)?;
//                 tracing::info!(
//                     "pre-confirmation will be sent for slot {} to validator with index {} at url {}",
//                     duty.slot,
//                     duty.validator_index,
//                     proposer_rpc,
//                 );
//                 break;
//             }
//             // Such validator index is not registered, continue
//             Err(ContractError::Revert(_)) => {
//                 tracing::warn!(
//                     "validator index {} not registered, skipping",
//                     duty.validator_index
//                 );
//                 continue;
//             }
//             Err(e) => {
//                 return Err(eyre!(
//                     "unexpected error while calling registry contract: {:?}",
//                     e
//                 ));
//             }
//         }
//     }

//     if next_preconfer_slot == 0 {
//         return Err(eyre!("no registered validators found in the lookahead"));
//     };

//     Ok((proposer_rpc, next_preconfer_slot))
// }

// /// Tries to parse the registered validator's sidecars URL from the token returned
// /// by the view call to the registry smart contract
// ///
// /// Reference: https://github.com/chainbound/bolt/blob/e71c61aa97dcd7b08fad23067caf18bc90a582cd/bolt-contracts/src/interfaces/IBoltRegistry.sol#L6-L16
// pub fn try_parse_url_from_token(token: Token) -> Result<String> {
//     let Token::Tuple(registrant_struct_fields) = token else {
//         return Err(eyre!("register call result is not a struct"));
//     };

//     let Some(metadata_token) = registrant_struct_fields.last() else {
//         return Err(eyre!("register call result is a struct with no fields"));
//     };

//     let Token::Tuple(metadata_fields) = metadata_token else {
//         return Err(eyre!(
//             "register call result is a struct without the `metadata` field"
//         ));
//     };

//     let Some(rpc_token) = metadata_fields.first() else {
//         return Err(eyre!(
//             "register call result has a `metadata` field, but the struct is empty"
//         ));
//     };

//     let Token::String(rpc) = rpc_token else {
//         return Err(eyre!(
//             "register call result has a `metadata` field, but its `rpc` property is not a string"
//         ));
//     };

//     Ok(rpc.clone())
// }
