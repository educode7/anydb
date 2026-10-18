//! Support fakes for the `connection` module tests (in-memory only:
//! deterministic, no sleeps, no third parties).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

pub use anydb_connections::connection::api::ConnectionModule;
pub use anydb_connections::connection::domain::ports::connection_events::{
    ConnectionEventKind, ConnectionEvents,
};
pub use anydb_connections::connection::domain::ports::secrets_store::SecretsStore;
pub use anydb_shared::ConnectionError;
pub use anydb_shared::driver::descriptor::DriverDescriptor;
pub use anydb_shared::driver::io::{ConnectionProperties, NetworkHandler, NetworkHandlerKind};
pub use anydb_shared::driver::spi::{DataSource, DataSourceMetadata, Driver, OpenRequest};
pub use anydb_shared::ports::Clock;

#[derive(Debug, Default, Clone)]
pub struct RecordingEvents {
    pub entries: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl ConnectionEvents for RecordingEvents {
    async fn on_event(&self, container_id: &str, kind: ConnectionEventKind) {
        self.entries
            .lock()
            .unwrap()
            .push(format!("{}:{:?}", container_id, kind));
    }
}

pub struct ScriptedSecrets {
    ok: bool,
}

impl ScriptedSecrets {
    pub fn ok() -> Arc<Self> {
        Arc::new(Self { ok: true })
    }

    pub fn failing() -> Arc<Self> {
        Arc::new(Self { ok: false })
    }
}

#[async_trait]
impl SecretsStore for ScriptedSecrets {
    async fn resolve(
        &self,
        _container_id: &str,
    ) -> Result<std::collections::HashMap<String, String>, ConnectionError> {
        if self.ok {
            let mut map = std::collections::HashMap::new();
            map.insert("user".to_owned(), "secret-user".to_owned());
            map.insert("password".to_owned(), "secret-password".to_owned());
            Ok(map)
        } else {
            Err(ConnectionError::MissingSecrets)
        }
    }
}

pub struct OkDriver {
    descriptor: DriverDescriptor,
    opens: Arc<AtomicUsize>,
}

impl OkDriver {
    pub fn new(thread_safe: bool) -> (Arc<Self>, Arc<AtomicUsize>) {
        let opens = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                descriptor: DriverDescriptor::new("fake", "Fake", thread_safe),
                opens: opens.clone(),
            }),
            opens,
        )
    }
}

#[async_trait]
impl Driver for OkDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    async fn open_data_source(
        &self,
        _request: OpenRequest,
    ) -> Result<Arc<dyn DataSource>, ConnectionError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(RecordingDataSource::new()))
    }
}

pub struct FailingDriver {
    descriptor: DriverDescriptor,
}

impl FailingDriver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            descriptor: DriverDescriptor::new("fake", "Fake", true),
        })
    }
}

#[async_trait]
impl Driver for FailingDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    async fn open_data_source(
        &self,
        _request: OpenRequest,
    ) -> Result<Arc<dyn DataSource>, ConnectionError> {
        Err(ConnectionError::DriverFailure)
    }
}

pub struct RecordingDataSource {
    pings: Arc<AtomicUsize>,
}

impl RecordingDataSource {
    pub fn new() -> Self {
        Self {
            pings: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl DataSource for RecordingDataSource {
    fn metadata(&self) -> DataSourceMetadata {
        DataSourceMetadata {
            product_name: "Fake".to_owned(),
            product_version: "0".to_owned(),
            driver_name: "fake".to_owned(),
        }
    }

    async fn ping(&self) -> Result<(), ConnectionError> {
        self.pings.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn close(&self) {}
}

pub struct TunnelHandler {
    pub applied: Arc<AtomicUsize>,
}

#[async_trait]
impl NetworkHandler for TunnelHandler {
    fn kind(&self) -> NetworkHandlerKind {
        NetworkHandlerKind::Tunnel
    }

    async fn initialize(
        &self,
        properties: &mut ConnectionProperties,
    ) -> Result<(), ConnectionError> {
        self.applied.fetch_add(1, Ordering::SeqCst);
        properties
            .settings
            .insert("via".to_owned(), "tunnel".to_owned());
        Ok(())
    }
}

pub fn module_with_secrets(secrets: Arc<dyn SecretsStore>) -> Arc<ConnectionModule> {
    let clock: Arc<dyn Clock> = Arc::new(anydb_shared::ports::SystemClock);
    ConnectionModule::new(
        clock,
        secrets,
        Arc::new(RecordingEvents::default()) as Arc<dyn ConnectionEvents>,
    )
}
