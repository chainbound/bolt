use std::time::{SystemTime, UNIX_EPOCH};

/// Get the current timestamp in seconds.
pub fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs()
}
