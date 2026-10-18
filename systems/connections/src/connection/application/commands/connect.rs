//! Connect command: the evidence digest 4.3 pipeline
//! (secrets -> events -> proxy -> tunnel -> open_data_source) under a
//! single-writer status rule.

use std::sync::Arc;

use anydb_shared::ConnectionError;
use anydb_shared::driver::io::NetworkHandlerKind;
use anydb_shared::driver::spi::OpenRequest;
use anydb_shared::ports::Clock;

use crate::connection::domain::entities::data_source_container::ContainerState;
use crate::connection::domain::errors::ConnectionResult;
use crate::connection::domain::ports::connection_events::{ConnectionEventKind, ConnectionEvents};
use crate::connection::domain::ports::secrets_store::SecretsStore;
use crate::connection::domain::value_objects::container_status::ContainerStatus;

/// Injected dependencies shared by every command of module `connection`.
/// Clone is manual because `dyn` fields do not `#[derive(Clone)]`.
pub struct ConnectionDependencies {
    pub clock: Arc<dyn Clock>,
    pub secrets: Arc<dyn SecretsStore>,
    pub events: Arc<dyn ConnectionEvents>,
}

impl Clone for ConnectionDependencies {
    fn clone(&self) -> Self {
        Self {
            clock: self.clock.clone(),
            secrets: self.secrets.clone(),
            events: self.events.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectOutcome {
    pub status: ContainerStatus,
    pub metadata: Option<anydb_shared::driver::spi::DataSourceMetadata>,
}

pub struct ConnectHandler;

impl ConnectHandler {
    pub async fn handle(
        container: Arc<ContainerState>,
        deps: &ConnectionDependencies,
    ) -> ConnectionResult<ConnectOutcome> {
        match container.status() {
            ContainerStatus::Connecting => return Err(ConnectionError::ConnectingInProgress),
            ContainerStatus::Connected => return Err(ConnectionError::AlreadyConnected),
            ContainerStatus::Disconnecting => return Err(ConnectionError::DisconnectingInProgress),
            ContainerStatus::Disconnected | ContainerStatus::Failed(_) => {}
        }

        container.set_status(ContainerStatus::Connecting);
        let outcome = Self::pipeline(&container, deps).await;
        match outcome {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                tracing::debug!(container_id = container.id(), ?error, "connect failed");
                container.mark_failed();
                Err(error)
            }
        }
    }

    async fn pipeline(
        container: &Arc<ContainerState>,
        deps: &ConnectionDependencies,
    ) -> ConnectionResult<ConnectOutcome> {
        deps.events
            .on_event(container.id(), ConnectionEventKind::BeforeConnect)
            .await;

        // Stage 1: secrets (shared credentials cache analog).
        let secrets = deps.secrets.resolve(container.id()).await?;
        let mut properties = container.properties();
        for (key, value) in secrets {
            properties.settings.insert(key, value);
        }

        // Stage 2: network handlers, proxy first (connect0 ordering).
        for handler in container
            .handlers()
            .iter()
            .filter(|h| h.kind() == NetworkHandlerKind::Proxy)
        {
            handler.initialize(&mut properties).await?;
        }
        for handler in container
            .handlers()
            .iter()
            .filter(|h| h.kind() == NetworkHandlerKind::Tunnel)
        {
            handler.initialize(&mut properties).await?;
        }
        container.replace_properties(properties.clone());

        // Stage 3: factory seam.
        let request = OpenRequest {
            container_id: container.id().to_owned(),
            target: properties.target,
            properties: properties.settings.clone(),
        };
        let data_source = container.driver().open_data_source(request).await?;

        deps.events
            .on_event(container.id(), ConnectionEventKind::AfterConnect)
            .await;

        let metadata = data_source.metadata();
        container.store_data_source(data_source);

        Ok(ConnectOutcome {
            status: ContainerStatus::Connected,
            metadata: Some(metadata),
        })
    }
}
