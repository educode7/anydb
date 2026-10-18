//! Bounded, in-order job queue: one worker processes jobs sequentially
//! (DBeaver job queue semantics). The worker task is spawned into the
//! caller-owned `JoinSet`, never detached.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::connection::application::jobs::{ConnectionJob, JobExecutor};
use crate::connection::domain::errors::ConnectionResult;
use anydb_shared::ConnectionError;

pub struct BoundJobQueue {
    tx: mpsc::Sender<ConnectionJob>,
}

impl BoundJobQueue {
    /// Serializes lifecycle work through one worker, supervised by `tasks`.
    pub fn spawn(executor: Arc<dyn JobExecutor>, capacity: usize, tasks: &mut JoinSet<()>) -> Self {
        let (tx, mut rx) = mpsc::channel::<ConnectionJob>(capacity.max(1));
        tasks.spawn(async move {
            while let Some(job) = rx.recv().await {
                let outcome = executor.execute(job).await;
                if let Err(error) = outcome {
                    tracing::debug!(?error, "connection job failed");
                }
            }
        });
        Self { tx }
    }

    pub async fn submit(&self, job: ConnectionJob) -> ConnectionResult<()> {
        self.tx
            .send(job)
            .await
            .map_err(|_| ConnectionError::Canceled)
    }
}
