#![allow(unused)]

use beacon_api_client::VersionedValue;
use ethereum_consensus::{
    builder::SignedValidatorRegistration,
    deneb::{
        self,
        mainnet::{BlobsBundle, SignedBlindedBeaconBlock},
    },
    types::mainnet::ExecutionPayload,
};
use reqwest::StatusCode;
use serde_json::Value;
use tokio::sync::watch;

use crate::{
    api::{builder::GetHeaderParams, spec::BuilderApiError},
    primitives::{
        BatchedSignedConstraints, GetPayloadResponse, PayloadAndBlobs, SignedBuilderBid,
        SignedDelegation, SignedRevocation,
    },
    BuilderApi, ConstraintsApi,
};

/// Create a `GetPayloadResponse` with a default `Deneb` execution payload.
pub fn make_get_payload_response() -> GetPayloadResponse {
    let execution_payload = ExecutionPayload::Deneb(deneb::ExecutionPayload::default());

    let blobs_bundle = BlobsBundle::default();

    GetPayloadResponse::Deneb(PayloadAndBlobs { execution_payload, blobs_bundle })
}

pub struct MockMevBoost {
    pub response_rx: watch::Receiver<Value>,
}

impl MockMevBoost {
    pub fn new() -> (Self, watch::Sender<Value>) {
        let (response_tx, response_rx) = watch::channel(Value::Null);
        (Self { response_rx }, response_tx)
    }
}

#[async_trait::async_trait]
impl BuilderApi for MockMevBoost {
    async fn status(&self) -> Result<StatusCode, BuilderApiError> {
        Err(BuilderApiError::Generic("MockMevBoost does not support getting status".to_string()))
    }

    async fn register_validators(
        &self,
        _registrations: Vec<SignedValidatorRegistration>,
    ) -> Result<(), BuilderApiError> {
        Err(BuilderApiError::Generic(
            "MockMevBoost does not support registering validators".to_string(),
        ))
    }

    async fn get_header(
        &self,
        _params: GetHeaderParams,
    ) -> Result<SignedBuilderBid, BuilderApiError> {
        let response = self.response_rx.borrow().clone();
        let bid = serde_json::from_value(response)?;
        Ok(bid)
    }

    async fn get_payload(
        &self,
        _signed_block: SignedBlindedBeaconBlock,
    ) -> Result<GetPayloadResponse, BuilderApiError> {
        let response = self.response_rx.borrow().clone();
        let payload = serde_json::from_value(response)?;
        Ok(payload)
    }
}

#[async_trait::async_trait]
impl ConstraintsApi for MockMevBoost {
    async fn submit_constraints(
        &self,
        _constraints: &BatchedSignedConstraints,
    ) -> Result<(), BuilderApiError> {
        Err(BuilderApiError::Generic(
            "MockMevBoost does not support submitting constraints".to_string(),
        ))
    }

    async fn get_header_with_proofs(
        &self,
        _params: GetHeaderParams,
    ) -> Result<VersionedValue<SignedBuilderBid>, BuilderApiError> {
        let response = self.response_rx.borrow().clone();
        let bid = serde_json::from_value(response)?;
        Ok(bid)
    }

    async fn delegate(&self, signed_data: SignedDelegation) -> Result<(), BuilderApiError> {
        unimplemented!()
    }

    async fn revoke(&self, signed_data: SignedRevocation) -> Result<(), BuilderApiError> {
        unimplemented!()
    }
}

#[test]
fn test_decode_get_payload_response() {
    let stringified =
        std::fs::read_to_string("./src/client/test_util/deneb_get_payload_response.json")
            .expect("failed to read get payload response file");

    let parsed_response: GetPayloadResponse =
        serde_json::from_str(&stringified).expect("failed to parse get payload response");
}
