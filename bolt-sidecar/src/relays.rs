use serde_json::Value;
use tokio::sync::broadcast;
use tracing::{debug, error, warn};

/// The endpoint for the relay constraints API (where to broadcast commitments).
const RELAY_CONSTRAINTS_ENDPOINT: &str = "/eth/v1/builder/constraints";

#[derive(Debug, Clone)]
pub enum RelayCommand {
    BroadcastCommitment { params: Value },
    Shutdown,
}

/// Component responsible for dispatching commands to all relays
pub struct RelayManager {
    cmd_tx: broadcast::Sender<RelayCommand>,
}

impl RelayManager {
    /// Create a new relay manager with the given endpoints and start the relay clients.
    /// This method will spawn a new background task for each relay client.
    pub fn new(endpoints: Vec<String>) -> Self {
        let (cmd_tx, _) = broadcast::channel(64);

        for endpoint in endpoints {
            let relay = Relay {
                cmd_rx: cmd_tx.subscribe(),
                api: RelayClient {
                    endpoint: endpoint.trim_end_matches('/').to_string(),
                    client: reqwest::Client::new(),
                },
            };
            tokio::spawn(relay.start());
        }

        Self { cmd_tx }
    }

    /// Broadcasts a commitment to all connected relays in the background.
    pub fn broadcast_commitment(&self, params: Value) {
        let _ = self
            .cmd_tx
            .send(RelayCommand::BroadcastCommitment { params });
    }

    /// Shuts down all relay clients gracefully.
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(RelayCommand::Shutdown);
    }
}

pub struct Relay<R> {
    cmd_rx: broadcast::Receiver<RelayCommand>,
    api: R,
}

pub trait RelayClientAPI {
    fn endpoint(&self) -> &str;

    fn broadcast_commitment(&self, params: Value);
}

impl<R: RelayClientAPI + Sync> Relay<R> {
    /// Start the relay client in a background task
    async fn start(mut self) {
        loop {
            tokio::select! {
            Ok(cmd) = self.cmd_rx.recv() => {
                    match cmd {
                        RelayCommand::BroadcastCommitment { params } => {
                            self.api.broadcast_commitment(params);
                        }
                        RelayCommand::Shutdown => {
                            warn!("Shutting down relay client: {}", self.api.endpoint());
                            break;
                        }
                    }
                },
            }
        }
    }
}

pub struct RelayClient {
    endpoint: String,
    client: reqwest::Client,
}

impl RelayClientAPI for RelayClient {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn broadcast_commitment(&self, params: Value) {
        let endpoint = format!("{}{}", self.endpoint, RELAY_CONSTRAINTS_ENDPOINT);
        let request = self.client.post(endpoint.clone()).json(&params);

        tokio::spawn(async move {
            let response = match request.send().await {
                Ok(res) => res,
                Err(e) => {
                    error!("Failed to broadcast commitment to {}: {}", endpoint, e);
                    return;
                }
            };

            debug!(
                "Broadcasted commitment to {} with status: {}",
                endpoint,
                response.status()
            );
        });
    }
}
