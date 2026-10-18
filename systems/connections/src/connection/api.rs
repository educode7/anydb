//! Module API: dependency wiring and the module's public surface
//! (`{module}_module_api.rs` analog). Exposes command dispatch and the weak
//! executor adapter for the job queue from the composition root.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::connection::application::commands::connect::ConnectHandler;
use crate::connection::application::commands::connect::ConnectOutcome;
use crate::connection::application::commands::connect::ConnectionDependencies;
use crate::connection::application::commands::disconnect::DisconnectHandler;
use crate::connection::application::commands::invalidate::InvalidateHandler;
use crate::connection::application::commands::invalidate::InvalidateScope;
use crate::connection::application::commands::keepalive::KeepAliveHandler;
use crate::connection::application::dtos::container_status_dto::ContainerStatusDto;
use crate::connection::application::jobs::ConnectionJob;
use crate::connection::application::jobs::JobExecutor;
use crate::connection::application::queries::get_status::StatusHandler;
use crate::connection::domain::entities::data_source_container::ContainerState;
use crate::connection::domain::errors::ConnectionResult;
use crate::connection::domain::ports::connection_events::ConnectionEvents;
use crate::connection::domain::ports::secrets_store::SecretsStore;
use crate::connection::infrastructure::in_memory_registry::ContainerRegistry;
use anydb_shared::ConnectionError;
use anydb_shared::ports::Clock;

#[derive(Clone)]
pub struct ConnectionModule {
    registry: Arc<ContainerRegistry>,
    dependencies: ConnectionDependencies,
}

impl ConnectionModule {
    pub fn new(
        clock: Arc<dyn Clock>,
        secrets: Arc<dyn SecretsStore>,
        events: Arc<dyn ConnectionEvents>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry: Arc::new(ContainerRegistry::new()),
            dependencies: ConnectionDependencies {
                clock,
                secrets,
                events,
            },
        })
    }

    pub fn dependencies(&self) -> &ConnectionDependencies {
        &self.dependencies
    }

    pub fn add_container(&self, container: Arc<ContainerState>) {
        self.registry.add(container);
    }

    pub fn container(&self, id: &str) -> Result<Arc<ContainerState>, ConnectionError> {
        self.registry.get(id)
    }

    pub fn container_ids(&self) -> Vec<String> {
        self.registry.ids()
    }

    pub async fn connect(&self, container_id: &str) -> ConnectionResult<ConnectOutcome> {
        let container = self.container(container_id)?;
        ConnectHandler::handle(container, &self.dependencies).await
    }

    pub async fn disconnect(&self, container_id: &str) -> ConnectionResult<()> {
        let container = self.container(container_id)?;
        DisconnectHandler::handle(container, &self.dependencies).await
    }

    pub async fn invalidate(
        &self,
        container_id: &str,
        scope: InvalidateScope,
    ) -> ConnectionResult<()> {
        let container = self.container(container_id)?;
        InvalidateHandler::handle(container, scope, &self.dependencies).await
    }

    pub async fn keep_alive(&self, container_id: &str, timeout: Duration) -> ConnectionResult<()> {
        let container = self.container(container_id)?;
        KeepAliveHandler::handle(container, timeout, &self.dependencies).await
    }

    pub fn status(&self, container_id: &str) -> ConnectionResult<ContainerStatusDto> {
        let container = self.container(container_id)?;
        Ok(StatusHandler.handle(container))
    }

    /// Job queue executor adapter bound to this module. Weak reference keeps
    /// module -> queue -> executor -> module from forming a strong cycle.
    pub fn job_executor(module: &Arc<Self>) -> Arc<dyn JobExecutor> {
        Arc::new(QueuedExecutor {
            module: Arc::downgrade(module),
        })
    }
}

struct QueuedExecutor {
    module: std::sync::Weak<ConnectionModule>,
}

#[async_trait]
impl JobExecutor for QueuedExecutor {
    async fn execute(&self, job: ConnectionJob) -> ConnectionResult<()> {
        let Some(module) = self.module.upgrade() else {
            return Err(ConnectionError::Canceled);
        };
        match job {
            ConnectionJob::Connect { container_id } => {
                module.connect(&container_id).await.map(|_| ())
            }
            ConnectionJob::Disconnect { container_id } => module.disconnect(&container_id).await,
            ConnectionJob::Invalidate {
                container_id,
                scope,
            } => module.invalidate(&container_id, scope).await,
        }
    }
}
