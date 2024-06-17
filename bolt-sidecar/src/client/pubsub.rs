use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use alloy::{ClientBuilder, WsConnect};
use alloy_json_rpc::RpcError;
use alloy_pubsub::PubSubFrontend;
use alloy_rpc_client as alloy;
use alloy_transport::TransportError;
use reqwest::Url;

/// Wrapper around an [`alloy::RpcClient`] that uses WS as the transport. Supports batching
/// JSON-RPC requests.
pub struct PubsubClient(alloy::RpcClient<PubSubFrontend>);

impl PubsubClient {
    /// Create a new `PubsubClient` with the given URL.
    pub async fn new(url: &str) -> Result<Self, RpcError<TransportError>> {
        let url = Url::from_str(url).unwrap();

        let client = ClientBuilder::default().ws(WsConnect::new(url)).await?;

        Ok(Self(client))
    }
}

impl Deref for PubsubClient {
    type Target = alloy::RpcClient<PubSubFrontend>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PubsubClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
