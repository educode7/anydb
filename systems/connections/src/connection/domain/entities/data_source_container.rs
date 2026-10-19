//! DBeaver `DataSourceDescriptor` analog: identity, declared driver,
//! pipeline configuration and container status.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use anydb_shared::driver::io::{ConnectionProperties, NetworkHandler};
use anydb_shared::driver::spi::{DataSource, Driver};

use crate::connection::domain::value_objects::container_status::ContainerStatus;

pub struct ContainerConfig {
    pub properties: ConnectionProperties,
    pub handlers: Vec<Arc<dyn NetworkHandler>>,
}

pub struct ContainerState {
    id: String,
    driver: Arc<dyn Driver>,
    config: RwLock<ContainerConfig>,
    status: RwLock<ContainerStatus>,
    connected: RwLock<Option<Arc<dyn DataSource>>>,
    /// Auto-restore policy (DBeaver monitor auto-connect analog): the
    /// monitor loop only reconciles containers flagged with it.
    auto_reconnect: RwLock<bool>,
}

impl fmt::Debug for ContainerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainerState")
            .field("id", &self.id)
            .field("status", &self.status())
            .finish()
    }
}

impl ContainerState {
    pub fn new(
        id: impl Into<String>,
        driver: Arc<dyn Driver>,
        config: ContainerConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            driver,
            config: RwLock::new(config),
            status: RwLock::new(ContainerStatus::Disconnected),
            connected: RwLock::new(None),
            auto_reconnect: RwLock::new(false),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn driver(&self) -> &Arc<dyn Driver> {
        &self.driver
    }

    pub fn status(&self) -> ContainerStatus {
        self.status
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Status transitions are only written by application commands, mirroring
    /// the DBeaver job layer single-writer rule.
    pub(crate) fn set_status(&self, status: ContainerStatus) {
        if let Ok(mut guard) = self.status.write() {
            *guard = status;
        }
    }

    pub(crate) fn mark_failed(&self) {
        // Censored on purpose: no secrets or bodies ever land in state.
        self.set_status(ContainerStatus::Failed("connect pipeline failure".into()));
    }

    pub fn properties(&self) -> ConnectionProperties {
        self.config
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .properties
            .clone()
    }

    pub(crate) fn replace_properties(&self, properties: ConnectionProperties) {
        if let Ok(mut guard) = self.config.write() {
            guard.properties = properties;
        }
    }

    pub fn handlers(&self) -> Vec<Arc<dyn NetworkHandler>> {
        self.config
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .handlers
            .clone()
    }

    pub fn data_source(&self) -> Option<Arc<dyn DataSource>> {
        self.connected
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn store_data_source(&self, data_source: Arc<dyn DataSource>) {
        if let Ok(mut guard) = self.connected.write() {
            *guard = Some(data_source);
        }
        self.set_status(ContainerStatus::Connected);
    }

    pub(crate) fn take_data_source(&self) -> Option<Arc<dyn DataSource>> {
        self.connected
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Auto-restore policy of the monitor loop; `false` by default so
    /// user-owned lifecycle stays user-owned.
    pub fn auto_reconnect(&self) -> bool {
        *self
            .auto_reconnect
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn set_auto_reconnect(&self, enabled: bool) {
        if let Ok(mut guard) = self.auto_reconnect.write() {
            *guard = enabled;
        }
    }
}
