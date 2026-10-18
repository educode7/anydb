//! Disconnect command: close the resolved data source and roll the status
//! back to `Disconnected`.

use std::sync::Arc;

use crate::connection::application::commands::connect::ConnectionDependencies;
use crate::connection::domain::entities::data_source_container::ContainerState;
use crate::connection::domain::errors::ConnectionResult;
use crate::connection::domain::ports::connection_events::ConnectionEventKind;
use crate::connection::domain::value_objects::container_status::ContainerStatus;
use anydb_shared::ConnectionError;

pub struct DisconnectHandler;

impl DisconnectHandler {
    pub async fn handle(
        container: Arc<ContainerState>,
        deps: &ConnectionDependencies,
    ) -> ConnectionResult<()> {
        match container.status() {
            ContainerStatus::Disconnected | ContainerStatus::Failed(_) => {
                return Err(ConnectionError::AlreadyDisconnected);
            }
            ContainerStatus::Disconnecting => {
                return Err(ConnectionError::DisconnectingInProgress);
            }
            ContainerStatus::Connecting => return Err(ConnectionError::ConnectingInProgress),
            ContainerStatus::Connected => {}
        }

        container.set_status(ContainerStatus::Disconnecting);
        if let Some(data_source) = container.take_data_source() {
            data_source.close().await;
        }
        container.set_status(ContainerStatus::Disconnected);
        deps.events
            .on_event(container.id(), ConnectionEventKind::AfterDisconnect)
            .await;
        Ok(())
    }
}
