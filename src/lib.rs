#![forbid(unsafe_code)]
//! `anydb` — async connection platform modeled from the DBeaver core
//! deconstruction (see `dbeaver-rea-analysis.md`).
//!
//! This crate is the ACA composition root: it wires infrastructure
//! implementations into the `connections` system and exposes the public
//! surface through `prelude`. HTTP/auth/presentation concerns do not apply
//! (library); the ACA security/observability rules map onto event sinks and
//! injected ports.

use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use tokio::task::JoinSet;

use anydb_connections::connection::api::ConnectionModule;
use anydb_connections::connection::application::commands::connect::ConnectOutcome;
use anydb_connections::connection::application::dtos::container_status_dto::ContainerStatusDto;
use anydb_connections::connection::application::jobs::ConnectionJob;
use anydb_connections::connection::infrastructure::job_queue::BoundJobQueue;
use anydb_connections::connection::infrastructure::monitor::{
    KeepAliveLoopConfig, LoopHandle, spawn_keepalive_loop,
};
use anydb_connections::execution::application::commands::execute_with_recovery::RecoveryRunner;
use anydb_connections::execution::domain::ports::invalidation_target::InvalidationTarget;
use anydb_connections::execution::domain::value_objects::recovery_policy::RecoveryPolicy;
use anydb_connections::execution::domain::value_objects::recovery_state::RecoveryState;
use anydb_shared::driver::io::{ConnectionProperties, NetworkHandler};
use anydb_shared::driver::spi::Driver;
use anydb_shared::ports::Clock;
use anydb_shared::ports::SystemClock;
use anydb_shared::{ConnectionError, ConnectionResult, RecoveryScope};

pub mod prelude {
    pub use crate::App;
    pub use anydb_connections::connection::api::ConnectionModule;
    pub use anydb_connections::connection::application::commands::connect::ConnectOutcome;
    pub use anydb_connections::connection::application::commands::invalidate::InvalidateScope;
    pub use anydb_connections::connection::application::dtos::container_status_dto::ContainerStatusDto;
    pub use anydb_connections::connection::application::jobs::ConnectionJob;
    pub use anydb_connections::connection::domain::entities::data_source_container::{
        ContainerConfig, ContainerState,
    };
    pub use anydb_connections::connection::domain::ports::connection_events::{
        ConnectionEventKind, ConnectionEvents,
    };
    pub use anydb_connections::connection::domain::ports::secrets_store::SecretsStore;
    pub use anydb_connections::connection::infrastructure::in_memory_registry::ContainerRegistry;
    pub use anydb_connections::connection::infrastructure::in_memory_secrets::InMemorySecretsStore;
    pub use anydb_connections::connection::infrastructure::job_queue::BoundJobQueue;
    pub use anydb_connections::connection::infrastructure::monitor::KeepAliveLoopConfig;
    pub use anydb_connections::connection::infrastructure::noop_events::NoOpEvents;
    pub use anydb_connections::execution::application::commands::execute_with_recovery::RecoveryRunner;
    pub use anydb_connections::execution::domain::ports::error_classifier::ErrorClassifier;
    pub use anydb_connections::execution::domain::ports::invalidation_target::InvalidationTarget;
    pub use anydb_connections::execution::domain::value_objects::recovery_policy::RecoveryPolicy;
    pub use anydb_connections::execution::domain::value_objects::recovery_state::RecoveryState;
    pub use anydb_connections::execution::domain::value_objects::statement_gate::StatementGate;
    pub use anydb_shared::driver::descriptor::DriverDescriptor;
    pub use anydb_shared::driver::io::{ConnectionProperties, NetworkHandler, NetworkHandlerKind};
    pub use anydb_shared::driver::spi::{DataSource, DataSourceMetadata, Driver, OpenRequest};
    pub use anydb_shared::ports::{Clock, SystemClock};
    pub use anydb_shared::{ConnectionError, ConnectionResult, ErrorType, RecoveryScope};
}

pub struct App {
    module: Arc<ConnectionModule>,
    queue: BoundJobQueue,
    recovery_policy: RecoveryPolicy,
    /// Supervised background tasks (job worker, keepalive loops). Shutdown
    /// drains this set; nothing is spawned detached. Std mutex: `spawn` is
    /// `&self`, no await is ever held while locked.
    tasks: StdMutex<JoinSet<()>>,
    /// Cancel handles for spawned background loops.
    loops: StdMutex<Vec<LoopHandle>>,
}

impl App {
    pub fn new(
        secrets: Arc<dyn anydb_connections::connection::domain::ports::secrets_store::SecretsStore>,
        events: Arc<
            dyn anydb_connections::connection::domain::ports::connection_events::ConnectionEvents,
        >,
    ) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let module = ConnectionModule::new(clock, secrets, events);
        let executor = ConnectionModule::job_executor(&module);
        // Queue worker joins the supervised task set (ACA operations rule:
        // no detached spawns); drained on `shutdown`.
        let mut tasks = JoinSet::new();
        let queue = BoundJobQueue::spawn(executor, 32, &mut tasks);
        Self {
            module,
            queue,
            recovery_policy: RecoveryPolicy::default(),
            tasks: StdMutex::new(tasks),
            loops: StdMutex::new(Vec::new()),
        }
    }

    pub fn set_recovery_policy(&mut self, policy: RecoveryPolicy) {
        self.recovery_policy = policy;
    }

    /// Spawns a supervised keepalive sweep (DBeaver `KeepAlivePingJob`
    /// analog). The handle is stored so `shutdown` cancels it.
    pub fn spawn_keepalive_loop(&self, config: KeepAliveLoopConfig) {
        let handle = {
            let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
            spawn_keepalive_loop(&self.module, config, &mut tasks)
        };
        self.loops
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(handle);
    }

    /// Declares a container backed by a driver and its pipeline config.
    pub fn add_container(
        &self,
        driver: Arc<dyn Driver>,
        container_id: impl Into<String>,
        properties: ConnectionProperties,
        handlers: Vec<Arc<dyn NetworkHandler>>,
    ) {
        let container = anydb_connections::connection::domain::entities::data_source_container::ContainerState::new(
            container_id,
            driver,
            anydb_connections::connection::domain::entities::data_source_container::ContainerConfig {
                properties,
                handlers,
            },
        );
        self.module.add_container(container);
    }

    pub fn container(
        &self,
        container_id: &str,
    ) -> ConnectionResult<
        Arc<anydb_connections::connection::domain::entities::data_source_container::ContainerState>,
    > {
        self.module.container(container_id)
    }

    /// Queues lifecycle work through the serialized job queue.
    pub async fn enqueue(&self, job: ConnectionJob) -> ConnectionResult<()> {
        self.queue.submit(job).await
    }

    pub async fn connect(&self, container_id: &str) -> ConnectionResult<ConnectOutcome> {
        self.module.connect(container_id).await
    }

    pub async fn disconnect(&self, container_id: &str) -> ConnectionResult<()> {
        self.module.disconnect(container_id).await
    }

    pub fn status(&self, container_id: &str) -> ConnectionResult<ContainerStatusDto> {
        self.module.status(container_id)
    }

    /// Statement execution through the bounded recovery runner, with
    /// invalidation bridged back into the `connection` module through its
    /// declared port (cross-module call via own-module port, ACA rule).
    pub async fn execute_with_recovery<T, Fut, F>(
        &self,
        container_id: &str,
        mut operation: F,
    ) -> ConnectionResult<T>
    where
        Fut: Future<Output = ConnectionResult<T>> + Send,
        F: FnMut() -> Fut,
    {
        // Validate the container exists before running attempts.
        self.module.container(container_id)?;
        let runner = self.recovery_runner(container_id);
        let mut state = RecoveryState::new();
        runner
            .run(&mut state, move || {
                let op = &mut operation;
                op()
            })
            .await
    }

    fn recovery_runner(&self, container_id: &str) -> RecoveryRunner {
        RecoveryRunner {
            container_id: container_id.to_owned(),
            policy: self.recovery_policy,
            classifier: Arc::new(
                anydb_connections::execution::infrastructure::default_error_classifier::DefaultErrorClassifier,
            ),
            invalidator: Arc::new(InvalidationBridge {
                module: Arc::downgrade(&self.module),
            }),
        }
    }

    /// Graceful shutdown: cancel background loops, close the queue and the
    /// module (their tasks hold `Weak` and exit), then drain the task set.
    pub async fn shutdown(self) {
        self.loops
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        drop(self.queue);
        drop(self.module);
        let mut tasks = self
            .tasks
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        while let Some(task) = tasks.join_next().await {
            if let Err(error) = task {
                tracing::debug!(?error, "background task ended abnormally");
            }
        }
    }
}

/// Bridges execution-side invalidation into connection commands. Lives in
/// the composition root because it crosses a module boundary via the
/// declared `InvalidationTarget` port only.
struct InvalidationBridge {
    module: std::sync::Weak<ConnectionModule>,
}

#[async_trait::async_trait]
impl InvalidationTarget for InvalidationBridge {
    async fn invalidate(&self, scope: RecoveryScope, container_id: &str) -> ConnectionResult<()> {
        let Some(module) = self.module.upgrade() else {
            return Err(ConnectionError::Canceled);
        };
        let scope = match scope {
            RecoveryScope::Transactions => {
                anydb_connections::connection::application::commands::invalidate::InvalidateScope::Transactions
            }
            RecoveryScope::DataSource => {
                anydb_connections::connection::application::commands::invalidate::InvalidateScope::DataSource
            }
        };
        module.invalidate(container_id, scope).await
    }
}
