//! Invalidate command (DBeaver `InvalidateJob` analog): drop transactions or
//! the whole data source so the next use reconnects.

use std::sync::Arc;

use crate::connection::application::commands::connect::ConnectionDependencies;
use crate::connection::domain::entities::data_source_container::ContainerState;
use crate::connection::domain::errors::ConnectionResult;
use crate::connection::domain::ports::connection_events::ConnectionEventKind;
use crate::connection::domain::value_objects::container_status::ContainerStatus;
use anydb_shared::ConnectionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidateScope {
    Transactions,
    DataSource,
}

pub struct InvalidateHandler;

impl InvalidateHandler {
    pub async fn handle(
        container: Arc<ContainerState>,
        scope: InvalidateScope,
        deps: &ConnectionDependencies,
    ) -> ConnectionResult<()> {
        if container.data_source().is_none() {
            return Err(ConnectionError::AlreadyDisconnected);
        }

        match scope {
            InvalidateScope::Transactions => {
                deps.events
                    .on_event(container.id(), ConnectionEventKind::InvalidatedTransaction)
                    .await;
            }
            InvalidateScope::DataSource => {
                if let Some(data_source) = container.take_data_source() {
                    data_source.close().await;
                }
                container.set_status(ContainerStatus::Disconnected);
                deps.events
                    .on_event(container.id(), ConnectionEventKind::InvalidatedDataSource)
                    .await;
            }
        }
        Ok(())
    }
}
