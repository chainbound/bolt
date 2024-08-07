use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use alloy::rpc::types::beacon::events::HeadEvent;
use beacon_api_client::Topic;
use futures::StreamExt;
use tokio::{sync::broadcast, task::AbortHandle, time::sleep};
use tracing::warn;

use crate::BeaconClient;

/// The delay between retries when attempting to reconnect to the beacon client
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Simple actor to keep track of the most recent head of the beacon chain
/// and broadcast updates to its subscribers.
///
/// Durability: the tracker will always attempt to reconnect to the provided
/// beacon client URL in case of disconnection or other errors.
#[derive(Debug)]
pub struct HeadTracker {
    /// Channel to receive updates of the "Head" beacon topic
    new_heads_rx: broadcast::Receiver<HeadEvent>,
    /// The genesis timestamp of the beacon chain, used for calculating proposal times
    beacon_genesis_timestamp: Arc<AtomicU64>,
    /// Handle to the background task that listens for new head events.
    /// Kept to allow for graceful shutdown.
    quit: AbortHandle,
}

/// A topic for subscribing to new head events
#[derive(Debug)]
pub struct NewHeadsTopic;

impl Topic for NewHeadsTopic {
    const NAME: &'static str = "head";

    type Data = HeadEvent;
}

impl HeadTracker {
    /// Create a new `HeadTracker` with the given beacon client HTTP URL and
    /// start listening for new head events in the background
    pub fn start(beacon_client: BeaconClient) -> Self {
        let (new_heads_tx, new_heads_rx) = broadcast::channel(32);

        let beacon_genesis_timestamp = Arc::new(AtomicU64::new(0));
        let beacon_genesis_timestamp_clone = beacon_genesis_timestamp.clone();

        let task = tokio::spawn(async move {
            loop {
                // First, try to get the genesis timestamp and cache it.
                let genesis_time = loop {
                    match beacon_client.get_genesis_details().await {
                        Ok(genesis_info) => break genesis_info.genesis_time,
                        Err(err) => {
                            warn!(?err, "failed to get genesis details");
                            sleep(RETRY_DELAY).await;
                            continue;
                        }
                    }
                };
                beacon_genesis_timestamp_clone.store(genesis_time, Ordering::Relaxed);

                let mut event_stream = match beacon_client.get_events::<NewHeadsTopic>().await {
                    Ok(events) => events,
                    Err(err) => {
                        warn!(?err, "failed to subscribe to new heads topic, retrying...");
                        sleep(RETRY_DELAY).await;
                        continue;
                    }
                };

                let event = match event_stream.next().await {
                    Some(Ok(event)) => event,
                    Some(Err(err)) => {
                        warn!(?err, "error reading new head event stream, retrying...");
                        sleep(RETRY_DELAY).await;
                        continue;
                    }
                    None => {
                        warn!("new head event stream ended, retrying...");
                        sleep(RETRY_DELAY).await;
                        continue;
                    }
                };

                if let Err(err) = new_heads_tx.send(event) {
                    warn!(?err, "failed to broadcast new head event to subscribers");
                }
            }
        });

        Self { new_heads_rx, beacon_genesis_timestamp, quit: task.abort_handle() }
    }

    /// Stop the tracker and cleanup resources
    pub fn stop(self) {
        self.quit.abort();
    }

    /// Get the next head event from the tracker
    pub async fn next_head(&mut self) -> Result<HeadEvent, broadcast::error::RecvError> {
        self.new_heads_rx.recv().await
    }

    /// Subscribe to new head events from the tracker
    ///
    /// The returned channel will NOT contain any previously emitted events cached in
    /// the tracker, but only new ones received after the call to this method
    pub fn subscribe_new_heads(&self) -> broadcast::Receiver<HeadEvent> {
        self.new_heads_rx.resubscribe()
    }

    /// Get the genesis timestamp of the beacon chain
    pub fn beacon_genesis_timestamp(&self) -> u64 {
        self.beacon_genesis_timestamp.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use reqwest::Url;
    use tracing::warn;

    use crate::{
        state::head_tracker::HeadTracker, test_util::try_get_beacon_api_url, BeaconClient,
    };

    #[tokio::test]
    async fn test_fetch_next_beacon_head() -> eyre::Result<()> {
        let _ = tracing_subscriber::fmt::try_init();

        let Some(url) = try_get_beacon_api_url().await else {
            warn!("skipping test: beacon API URL is not reachable");
            return Ok(());
        };

        let beacon_client = BeaconClient::new(Url::parse(url).unwrap());
        let mut tracker = HeadTracker::start(beacon_client);

        let head = tracker.next_head().await?;

        assert!(head.slot > 0);
        assert!(!head.block.is_empty());

        Ok(())
    }
}
