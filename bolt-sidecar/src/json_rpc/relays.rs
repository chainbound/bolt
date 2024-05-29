use tracing::{info, warn};

use super::{api::JsonRpcApi, types::PreconfirmationRequestParams};

/// Path to the constraints endpoint on the relay.
const CONSTRAINTS_PATH: &str = "/eth/v1/builder/constraints";

impl JsonRpcApi {
    /// Broadcast a preconfirmation request to all connected relays.
    /// This is a fire-and-forget operation that runs in the background.
    pub(crate) fn broadcast_request_to_connected_relays(
        &self,
        params: PreconfirmationRequestParams,
    ) {
        let relays = self.relays.clone();

        tokio::task::spawn(async move {
            for relay_url in &relays {
                match reqwest::Client::new()
                    .post(format!("{}{}", relay_url, CONSTRAINTS_PATH))
                    .body(serde_json::to_string(&params).unwrap())
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            warn!(
                                "failed to broadcast preconfirmation request to relay: {}",
                                relay_url
                            );
                        } else {
                            info!(
                                "broadcasted preconfirmation request to relay: {}",
                                relay_url
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "failed to broadcast preconfirmation request to relay: {}",
                            e
                        );
                    }
                };
            }
        });
    }
}
