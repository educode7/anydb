//! Serialized job queue tests: deterministic completion signaling via
//! channels, no sleeps.

use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

use anydb_connections::connection::application::jobs::{ConnectionJob, JobExecutor};
use anydb_connections::connection::infrastructure::job_queue::BoundJobQueue;
use anydb_shared::ConnectionError;
use tokio::task::JoinSet;

struct RecordingExecutor {
    seen: Arc<Mutex<Vec<ConnectionJob>>>,
    signal: mpsc::UnboundedSender<()>,
}

#[async_trait::async_trait]
impl JobExecutor for RecordingExecutor {
    async fn execute(&self, job: ConnectionJob) -> Result<(), ConnectionError> {
        self.seen.lock().await.push(job);
        let _ = self.signal.send(());
        Ok(())
    }
}

#[tokio::test]
async fn queue_processes_every_job_in_order() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (signal, mut completed) = mpsc::unbounded_channel();
    let executor = Arc::new(RecordingExecutor {
        seen: seen.clone(),
        signal,
    }) as Arc<dyn JobExecutor>;

    let mut tasks = JoinSet::new();
    let queue = BoundJobQueue::spawn(executor, 8, &mut tasks);

    for i in 0..4 {
        let job = ConnectionJob::Connect {
            container_id: format!("ds{}", i),
        };
        queue.submit(job).await.expect("submit ok");
    }

    for _ in 0..4 {
        completed.recv().await.expect("worker alive");
    }

    let completed_jobs = seen.lock().await;
    assert_eq!(completed_jobs.len(), 4);
    for (i, job) in completed_jobs.iter().enumerate() {
        match job {
            ConnectionJob::Connect { container_id } => {
                assert_eq!(container_id, &format!("ds{}", i));
            }
            _ => panic!("unexpected job"),
        }
    }
}
