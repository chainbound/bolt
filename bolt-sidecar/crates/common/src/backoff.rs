use std::{future::Future, time::Duration};

use tokio_retry::{
    strategy::{jitter, ExponentialBackoff},
    Retry, RetryIf,
};

/// Configuration for retry
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Initial delay in milliseconds before the first retry
    pub initial_delay_ms: u64,
    /// Maximum delay in seconds between retries
    pub max_delay_secs: u64,
    /// Multiplication factor for exponential backoff
    pub factor: u64,
}

/// Retry a future with exponential backoff and jitter.
///
/// If `max_retries` is `None`, the future will be retried indefinitely.
pub async fn retry_with_backoff<F, T, E>(
    max_retries: Option<usize>,
    config: Option<RetryConfig>,
    fut: impl Fn() -> F,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let config =
        config.unwrap_or(RetryConfig { initial_delay_ms: 100, max_delay_secs: 1, factor: 2 });

    let backoff = ExponentialBackoff::from_millis(config.initial_delay_ms)
        .factor(config.factor)
        .max_delay(Duration::from_secs(config.max_delay_secs));

    match max_retries {
        Some(max_retries) => {
            let backoff = backoff.take(max_retries).map(jitter);
            Retry::spawn(backoff, fut).await
        }
        None => Retry::spawn(backoff, fut).await,
    }
}

/// Retry a future with exponential backoff and jitter if the error matches a condition.
///
/// If `max_retries` is `None`, the future will be retried indefinitely.
pub async fn retry_with_backoff_if<F, T, E>(
    max_retries: Option<usize>,
    config: Option<RetryConfig>,
    fut: impl Fn() -> F,
    condition: impl FnMut(&E) -> bool,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let config =
        config.unwrap_or(RetryConfig { initial_delay_ms: 100, max_delay_secs: 1, factor: 2 });

    let backoff = ExponentialBackoff::from_millis(config.initial_delay_ms)
        .factor(config.factor)
        .max_delay(Duration::from_secs(config.max_delay_secs));

    match max_retries {
        Some(max_retries) => {
            let backoff = backoff.take(max_retries).map(jitter);
            RetryIf::spawn(backoff, fut, condition).await
        }
        None => RetryIf::spawn(backoff, fut, condition).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use thiserror::Error;
    use tokio::{
        sync::Mutex,
        time::{Duration, Instant},
    };

    #[derive(Debug, Error)]
    #[error("mock error")]
    struct MockError;

    // Helper struct to count attempts and control failure/success behavior
    struct Counter {
        count: usize,
        fail_until: usize,
    }

    impl Counter {
        fn new(fail_until: usize) -> Self {
            Self { count: 0, fail_until }
        }

        async fn retryable_fn(&mut self) -> Result<(), MockError> {
            self.count += 1;
            if self.count <= self.fail_until {
                Err(MockError)
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_retry_success_without_retry() {
        let counter = Arc::new(Mutex::new(Counter::new(0)));

        let result = retry_with_backoff(Some(5), None, || {
            let counter = Arc::clone(&counter);
            async move {
                let mut counter = counter.lock().await;
                counter.retryable_fn().await
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(counter.lock().await.count, 1, "Should succeed on first attempt");
    }

    #[tokio::test]
    async fn test_retry_until_success() {
        let counter = Arc::new(Mutex::new(Counter::new(3))); // Fail 3 times, succeed on 4th

        let result = retry_with_backoff(Some(5), None, || async {
            let counter = Arc::clone(&counter);
            let mut counter = counter.lock().await;
            counter.retryable_fn().await
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(counter.lock().await.count, 4, "Should retry until success on 4th attempt");
    }

    #[tokio::test]
    async fn test_retry_until_success_with_condition() {
        let counter = Arc::new(Mutex::new(Counter::new(3))); // Fail 3 times, succeed on 4th

        let result = retry_with_backoff_if(
            Some(5),
            None,
            || async {
                let counter = Arc::clone(&counter);
                let mut counter = counter.lock().await;
                counter.retryable_fn().await
            },
            |err| matches!(err, MockError),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(counter.lock().await.count, 4, "Should retry until success on 4th attempt");
    }

    #[tokio::test]
    async fn test_max_retries_reached() {
        let counter = Arc::new(Mutex::new(Counter::new(5))); // Fail 5 times, max retries = 3

        let result = retry_with_backoff(Some(3), None, || {
            let counter = Arc::clone(&counter);
            async move {
                let mut counter = counter.lock().await;
                counter.retryable_fn().await
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(counter.lock().await.count, 4, "Should stop after max retries are reached");
    }

    #[tokio::test]
    #[ignore = "Flaky test, jitter can influence outcome"]
    async fn test_exponential_backoff_timing() {
        let counter = Arc::new(Mutex::new(Counter::new(3))); // Fail 3 times, succeed on 4th
        let start_time = Instant::now();

        let result = retry_with_backoff(Some(5), None, || {
            let counter = Arc::clone(&counter);
            async move {
                let mut counter = counter.lock().await;
                counter.retryable_fn().await
            }
        })
        .await;

        assert!(result.is_ok());
        let elapsed = start_time.elapsed();
        assert!(
            elapsed >= Duration::from_millis(700),
            "Total backoff duration should be at least 700ms"
        );
    }
}
