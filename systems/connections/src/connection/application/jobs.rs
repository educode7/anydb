//! Serialized job queue contract (DBeaver `runtime/jobs` analog):
//! connection lifecycle work executes one job at a time, in order.

use async_trait::async_trait;

use crate::connection::application::commands::invalidate::InvalidateScope;
use crate::connection::domain::errors::ConnectionResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionJob {
    Connect {
        container_id: String,
    },
    Disconnect {
        container_id: String,
    },
    Invalidate {
        container_id: String,
        scope: InvalidateScope,
    },
}

#[async_trait]
pub trait JobExecutor: Send + Sync {
    async fn execute(&self, job: ConnectionJob) -> ConnectionResult<()>;
}
