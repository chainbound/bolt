trait EventsClient {
    type PreconfRequested;
    type PreconfConfirmed;

    fn preconf_requested(&self, event: Self::PreconfRequested);
    fn preconf_confirmed(&self, event: Self::PreconfConfirmed);
}

struct RemoteEventsClient {
    url: String,
    client: reqwest::Client,
}

impl RemoteEventsClient {
    fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }
}
