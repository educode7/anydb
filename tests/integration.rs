//! Integration test against `anydb::App` with in-memory fakes only:
//! connect -> execute with recovery (bridge invalidation) -> disconnect.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anydb::prelude::*;
use tokio::sync::Mutex as AsyncMutex;

struct RecordingEvents {
    entries: Arc<AsyncMutex<Vec<String>>>,
}

impl RecordingEvents {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: Arc::new(AsyncMutex::new(Vec::new())),
        })
    }
}

#[async_trait::async_trait]
impl ConnectionEvents for RecordingEvents {
    async fn on_event(&self, container_id: &str, kind: ConnectionEventKind) {
        self.entries
            .lock()
            .await
            .push(format!("{}:{:?}", container_id, kind));
    }
}

struct MemorySecrets {
    entries: std::sync::Mutex<HashMap<String, HashMap<String, String>>>,
}

impl MemorySecrets {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: std::sync::Mutex::new(HashMap::new()),
        })
    }

    pub fn register(&self, container_id: &str) {
        self.entries
            .lock()
            .unwrap()
            .insert(container_id.to_owned(), HashMap::new());
    }
}

#[async_trait::async_trait]
impl SecretsStore for MemorySecrets {
    async fn resolve(&self, container_id: &str) -> ConnectionResult<HashMap<String, String>> {
        self.entries
            .lock()
            .unwrap()
            .get(container_id)
            .cloned()
            .ok_or(ConnectionError::MissingSecrets)
    }
}

struct OkDriver {
    descriptor: DriverDescriptor,
    opens: Arc<AtomicUsize>,
}

impl OkDriver {
    pub fn new() -> (Arc<Self>, Arc<AtomicUsize>) {
        let opens = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                descriptor: DriverDescriptor::new("fake", "Fake", true),
                opens: opens.clone(),
            }),
            opens,
        )
    }
}

#[async_trait::async_trait]
impl Driver for OkDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    async fn open_data_source(
        &self,
        _request: OpenRequest,
    ) -> ConnectionResult<Arc<dyn DataSource>> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(MetadataSource) as Arc<dyn DataSource>)
    }
}

struct MetadataSource;

#[async_trait::async_trait]
impl DataSource for MetadataSource {
    fn metadata(&self) -> DataSourceMetadata {
        DataSourceMetadata {
            product_name: "Fake".into(),
            product_version: "0".into(),
            driver_name: "fake".into(),
        }
    }

    async fn ping(&self) -> ConnectionResult<()> {
        Ok(())
    }

    async fn close(&self) {}
}

#[tokio::test]
async fn end_to_end_connect_execute_recover_disconnect() {
    let events = RecordingEvents::new();
    let secrets = MemorySecrets::new();
    secrets.register("ds1");
    let secrets_dyn: Arc<dyn SecretsStore> = secrets;
    let events_dyn: Arc<dyn ConnectionEvents> = events.clone();
    let app = App::new(secrets_dyn, events_dyn);
    let (driver, opens) = OkDriver::new();

    app.add_container(
        driver,
        "ds1",
        ConnectionProperties::new("fake://host/db"),
        vec![],
    );

    let outcome = app.connect("ds1").await.expect("connect ok");
    assert_eq!(outcome.status, anydb_connections::connection::domain::value_objects::container_status::ContainerStatus::Connected);
    assert_eq!(opens.load(Ordering::SeqCst), 1);

    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let result = app
        .execute_with_recovery("ds1", move || {
            let attempt = counter.fetch_add(1, Ordering::SeqCst);
            let fut: Pin<Box<dyn Future<Output = ConnectionResult<i32>> + Send>> = if attempt < 2 {
                Box::pin(async { Err(ConnectionError::NetworkFailure) })
            } else {
                Box::pin(async { Ok(42) })
            };
            fut
        })
        .await
        .expect("recovery resolves after invalidations");
    assert_eq!(result, 42);

    // The ConnectionLost recovery invalidated the data source (DBeaver
    // `invalidateDataSource(false, true)` analog): container is disconnected.
    let status = app.status("ds1").expect("status ok");
    assert_eq!(status.status, "disconnected");

    // Reconnect and disconnect cleanly.
    app.connect("ds1").await.expect("reconnect ok");
    app.disconnect("ds1").await.expect("disconnect ok");

    let snapshot = events.entries.lock().await.clone();
    assert!(snapshot.contains(&"ds1:BeforeConnect".to_string()));
    assert!(snapshot.contains(&"ds1:AfterConnect".to_string()));
    assert!(snapshot.contains(&"ds1:AfterDisconnect".to_string()));
    assert!(opens.load(Ordering::SeqCst) >= 1);

    app.shutdown().await;
}
