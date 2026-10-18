//! Connection lifecycle events (DBeaver `DBPConnectionEventType`
//! BEFORE_CONNECT / AFTER_CONNECT analogs).

use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEventKind {
    BeforeConnect,
    AfterConnect,
    AfterDisconnect,
    InvalidatedTransaction,
    InvalidatedDataSource,
}

#[async_trait]
pub trait ConnectionEvents: Send + Sync {
    async fn on_event(&self, container_id: &str, kind: ConnectionEventKind);
}
