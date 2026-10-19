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

pub struct PingDriver {
    descriptor: DriverDescriptor,
    opens: Arc<AtomicUsize>,
    pings: Arc<AtomicUsize>,
    fail_ping: bool,
}
impl PingDriver {
    /// Returns the driver plus shared counters for opens and pings.
    pub fn new(fail_ping: bool) -> (Arc<Self>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let opens = Arc::new(AtomicUsize::new(0));
        let pings = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                descriptor: DriverDescriptor::new("ping", "Ping", true),
                opens: opens.clone(),
                pings: pings.clone(),
                fail_ping,
            }),
            opens,
            pings,
        )
    }
}

#[async_trait]
impl Driver for PingDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    async fn open_data_source(
        &self,
        _request: OpenRequest,
    ) -> Result<Arc<dyn DataSource>, ConnectionError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(PingSource {
            pings: self.pings.clone(),
            fail: self.fail_ping,
        }))
    }
}

struct PingSource {
    pings: Arc<AtomicUsize>,
    fail: bool,
}

#[async_trait]
impl DataSource for PingSource {
    fn metadata(&self) -> DataSourceMetadata {
        DataSourceMetadata {
            product_name: "Ping".to_owned(),
            product_version: "0".to_owned(),
            driver_name: "ping".to_owned(),
        }
    }

    async fn ping(&self) -> Result<(), ConnectionError> {
        self.pings.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(ConnectionError::NetworkFailure)
        } else {
            Ok(())
        }
    }

    async fn close(&self) {}
}

/// Ping source whose failure mode flips at runtime: the monitor tests
/// stage "dead network" and "recovered network" phases through one flag.
pub struct TogglePingDriver {
    descriptor: DriverDescriptor,
    opens: Arc<AtomicUsize>,
    pings: Arc<AtomicUsize>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

impl TogglePingDriver {
    /// Returns the driver plus the opens/pings counters and the failure
    /// flag (`true` = pings fail).
    pub fn new() -> (
        Arc<Self>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let opens = Arc::new(AtomicUsize::new(0));
        let pings = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
        (
            Arc::new(Self {
                descriptor: DriverDescriptor::new("ping", "Ping", true),
                opens: opens.clone(),
                pings: pings.clone(),
                fail: fail.clone(),
            }),
            opens,
            pings,
            fail,
        )
    }
}

#[async_trait]
impl Driver for TogglePingDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    async fn open_data_source(
        &self,
        _request: OpenRequest,
    ) -> Result<Arc<dyn DataSource>, ConnectionError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(TogglePingSource {
            pings: self.pings.clone(),
            fail: self.fail.clone(),
        }))
    }
}

struct TogglePingSource {
    pings: Arc<AtomicUsize>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl DataSource for TogglePingSource {
    fn metadata(&self) -> DataSourceMetadata {
        DataSourceMetadata {
            product_name: "Ping".to_owned(),
            product_version: "0".to_owned(),
            driver_name: "ping".to_owned(),
        }
    }

    async fn ping(&self) -> Result<(), ConnectionError> {
        self.pings.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(ConnectionError::NetworkFailure)
        } else {
            Ok(())
        }
    }

    async fn close(&self) {}
}

pub fn module_with_secrets(secrets: Arc<dyn SecretsStore>) -> Arc<ConnectionModule> {
    let clock: Arc<dyn Clock> = Arc::new(anydb_shared::ports::SystemClock);
    ConnectionModule::new(
        clock,
        secrets,
        Arc::new(RecordingEvents::default()) as Arc<dyn ConnectionEvents>,
    )
}

/// Module wired with a retained `RecordingEvents` handle so tests can
/// assert the event stream the commands emit.
pub fn module_with_events() -> (Arc<ConnectionModule>, Arc<RecordingEvents>) {
    let clock: Arc<dyn Clock> = Arc::new(anydb_shared::ports::SystemClock);
    let events = Arc::new(RecordingEvents::default());
    let module = ConnectionModule::new(
        clock,
        ScriptedSecrets::ok() as Arc<dyn SecretsStore>,
        events.clone() as Arc<dyn ConnectionEvents>,
    );
    (module, events)
}
