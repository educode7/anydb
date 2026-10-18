//! Keepalive command (DBeaver `KeepAlivePingJob` analog): bounded ping.

use std::sync::Arc;
use std::time::Duration;

use anydb_shared::ConnectionError;

use crate::connection::application::commands::connect::ConnectionDependencies;
use crate::connection::domain::entities::data_source_container::ContainerState;
use crate::connection::domain::errors::ConnectionResult;

pub struct KeepAliveHandler;

impl KeepAliveHandler {
    pub async fn handle(
        container: Arc<ContainerState>,
        timeout: Duration,
        _deps: &ConnectionDependencies,
    ) -> ConnectionResult<()> {
        let Some(data_source) = container.data_source() else {
            return Err(ConnectionError::AlreadyDisconnected);
        };
        match tokio::time::timeout(timeout, data_source.ping()).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ConnectionError::NetworkFailure),
        }
    }
}
