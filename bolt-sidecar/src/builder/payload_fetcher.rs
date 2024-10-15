use tokio::sync::{mpsc, oneshot};
use tracing::error;

use crate::primitives::{FetchPayloadRequest, PayloadAndBid};

/// A local payload fetcher that sends requests to a channel
/// and waits for a response on a oneshot channel.
#[derive(Debug, Clone)]
pub struct LocalPayloadFetcher {
    tx: mpsc::Sender<FetchPayloadRequest>,
}

impl LocalPayloadFetcher {
    /// Create a new `LocalPayloadFetcher` with the given channel to send fetch requests.
    pub fn new(tx: mpsc::Sender<FetchPayloadRequest>) -> Self {
        Self { tx }
    }
}

#[async_trait::async_trait]
impl PayloadFetcher for LocalPayloadFetcher {
    async fn fetch_payload(&self, slot: u64) -> Option<PayloadAndBid> {
        let (response_tx, response_rx) = oneshot::channel();

        let fetch_params = FetchPayloadRequest { response_tx, slot };
        self.tx.send(fetch_params).await.ok()?;

        match response_rx.await {
            Ok(res) => res,
            Err(e) => {
                error!(err = ?e, "Failed to fetch payload");
                None
            }
        }
    }
}

/// Interface for fetching payloads for the builder.
#[async_trait::async_trait]
pub trait PayloadFetcher {
    /// Fetch a payload for the given slot.
    async fn fetch_payload(&self, slot: u64) -> Option<PayloadAndBid>;
}

/// A payload fetcher that does nothing, used for testing.
#[derive(Debug)]
#[cfg(test)]
pub struct NoopPayloadFetcher;

#[cfg(test)]
#[async_trait::async_trait]
impl PayloadFetcher for NoopPayloadFetcher {
    async fn fetch_payload(&self, slot: u64) -> Option<PayloadAndBid> {
        tracing::info!(slot, "Fetch payload called");
        None
    }
}
