//! No-op event sink: default observability placeholder.

use crate::connection::domain::ports::connection_events::{ConnectionEventKind, ConnectionEvents};

#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpEvents;

#[async_trait::async_trait]
impl ConnectionEvents for NoOpEvents {
    async fn on_event(&self, _container_id: &str, _kind: ConnectionEventKind) {}
}
