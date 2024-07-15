//! The `state` module is responsible for keeping a local copy of relevant state that is needed
//! to simulate commitments against. It is updated on every block. It has both execution state and consensus state.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{future::poll_fn, Future, FutureExt};
use tokio::time::Sleep;

mod execution;
pub use execution::{ExecutionState, ValidationError};

/// Module to fetch state from the Execution layer.
pub mod fetcher;
pub use fetcher::StateClient;

/// Module to track the consensus state.
pub mod consensus;
pub use consensus::ConsensusState;

/// Module to track the head of the chain.
pub mod head_tracker;
pub use head_tracker::HeadTracker;

/// The deadline for a which a commitment is considered valid.
#[derive(Debug)]
pub struct CommitmentDeadline {
    slot: u64,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl CommitmentDeadline {
    /// Create a new deadline for a given slot and duration.
    pub fn new(slot: u64, duration: Duration) -> Self {
        let sleep = Some(Box::pin(tokio::time::sleep(duration)));
        Self { slot, sleep }
    }

    /// Poll the deadline until it is reached.
    pub async fn wait(&mut self) -> Option<u64> {
        let slot = poll_fn(|cx| self.poll_unpin(cx)).await;
        self.sleep = None;
        slot
    }

    /// Poll the deadline in an unpin context.
    pub fn poll_wait(&mut self, cx: &mut Context<'_>) -> Poll<Option<u64>> {
        self.poll_unpin(cx)
    }
}

/// Poll the deadline until it is reached.
///
/// - If already reached, the future will return `None` immediately.
/// - If not reached, the future will return `Some(slot)` when the deadline is reached.
impl Future for CommitmentDeadline {
    type Output = Option<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(ref mut sleep) = self.sleep else {
            return Poll::Ready(None);
        };

        match sleep.as_mut().poll(cx) {
            Poll::Ready(_) => Poll::Ready(Some(self.slot)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_commitment_deadline() {
        let time = std::time::Instant::now();
        let mut deadline = CommitmentDeadline::new(0, Duration::from_secs(1));

        let slot = deadline.wait().await;
        println!("Deadline reached. Passed {:?}", time.elapsed());
        assert_eq!(slot, Some(0));

        let time = std::time::Instant::now();
        let slot = deadline.wait().await;
        println!("Deadline reached. Passed {:?}", time.elapsed());
        assert_eq!(slot, None);
    }
}
