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

// ---------- per-driver classifier wiring ----------
// The classifier that mirrors the production anydb-postgres driver shape:
// SQLSTATE in ExecutionFailed decides the recovery type.
struct SqlstateClassifier;

impl ErrorClassifier for SqlstateClassifier {
    fn classify(&self, error: &ConnectionError) -> ErrorType {
        match error {
            ConnectionError::ExecutionFailed {
                sqlstate: Some(code),
                ..
            } if code == "25P02" => ErrorType::TransactionAborted,
            _ => ErrorType::default_classify(error),
        }
    }
}

/// Same `OkDriver` shape plus a driver-supplied classifier override.
struct ClassifierDriver {
    descriptor: DriverDescriptor,
}

impl ClassifierDriver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            descriptor: DriverDescriptor::new("fake-classified", "Fake Classified", true),
        })
    }
}

#[async_trait::async_trait]
impl Driver for ClassifierDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    fn error_classifier(&self) -> Option<Arc<dyn ErrorClassifier>> {
        Some(Arc::new(SqlstateClassifier))
    }

    async fn open_data_source(
        &self,
        _request: OpenRequest,
    ) -> ConnectionResult<Arc<dyn DataSource>> {
        Ok(Arc::new(MetadataSource) as Arc<dyn DataSource>)
    }
}

/// Drives `execute_with_recovery`: the first `failures` attempts fail with
/// `first`/`second` SQLSTATEs (attempt 0 vs the rest), the rest succeed.
async fn run_state_sequence(
    app: &App,
    container_id: &str,
    first: &'static str,
    second: &'static str,
    failures: usize,
) -> (ConnectionResult<()>, usize) {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let result = app
        .execute_with_recovery(container_id, move || {
            let attempt = counter.fetch_add(1, Ordering::SeqCst);
            let sqlstate = if attempt == 0 { first } else { second };
            let fut: Pin<Box<dyn Future<Output = ConnectionResult<()>> + Send>> =
                if attempt < failures {
                    Box::pin(async move {
                        Err(ConnectionError::ExecutionFailed {
                            sqlstate: Some(sqlstate.to_owned()),
                            message: "fake".into(),
                        })
                    })
                } else {
                    Box::pin(async { Ok(()) })
                };
            fut
        })
        .await;
    (result, attempts.load(Ordering::SeqCst))
}

#[tokio::test]
async fn driver_classifier_feeds_the_recovery_loop() {
    let events = RecordingEvents::new();
    let secrets = MemorySecrets::new();
    secrets.register("dsr1");
    let app = App::new(secrets, events);
    app.add_container(
        ClassifierDriver::new(),
        "dsr1",
        ConnectionProperties::new("classified://host/db"),
        vec![],
    );

    // First scenario: 25P02 (TransactionAborted) enables one retry.
    let (result, attempts) = run_state_sequence(&app, "dsr1", "25P02", "42601", 1).await;
    assert!(result.is_ok(), "the aborted statement must be retried");
    assert_eq!(attempts, 2);

    // Second scenario: 42601 is Normal — no retry, single attempt then the
    // error propagates.
    let (result, attempts) = run_state_sequence(&app, "dsr1", "42601", "42601", usize::MAX).await;
    assert!(result.is_err(), "Normal errors must not be retried");
    assert_eq!(attempts, 1);

    app.shutdown().await;
}

// ---------- cached statement execution through the pipeline ----------

/// Data source with a SQL-keyed cache behavior: same abort-once contract
/// as `TypedEchoSource`, but reached through the cached SPI method.
struct CachedEchoSource {
    calls: Arc<AtomicUsize>,
    rollbacks: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl DataSource for CachedEchoSource {
    fn metadata(&self) -> DataSourceMetadata {
        DataSourceMetadata {
            product_name: "Fake".into(),
            product_version: "0".into(),
            driver_name: "fake-cached".into(),
        }
    }

    async fn ping(&self) -> ConnectionResult<()> {
        Ok(())
    }

    async fn rollback_transaction(&self) -> ConnectionResult<()> {
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn execute_cached_statement_typed(
        &self,
        _sql: &str,
        _params: &[QueryParameter],
    ) -> ConnectionResult<TypedStatementResult> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            return Err(ConnectionError::ExecutionFailed {
                sqlstate: Some("25P02".to_owned()),
                message: "current transaction is aborted".into(),
            });
        }
        Ok(TypedStatementResult {
            columns: vec!["n".into()],
            rows: vec![vec![Some(TypedValue::Int8(9))]],
            command_tag: Some("SELECT 1".into()),
            affected_rows: Some(1),
        })
    }

    async fn close(&self) {}
}

/// Classified driver exposing the cached counting data source.
struct CachedDriver {
    descriptor: DriverDescriptor,
    calls: Arc<AtomicUsize>,
    rollbacks: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Driver for CachedDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    fn error_classifier(&self) -> Option<Arc<dyn ErrorClassifier>> {
        Some(Arc::new(SqlstateClassifier))
    }

    async fn open_data_source(
        &self,
        _request: OpenRequest,
    ) -> ConnectionResult<Arc<dyn DataSource>> {
        Ok(Arc::new(CachedEchoSource {
            calls: self.calls.clone(),
            rollbacks: self.rollbacks.clone(),
        }) as Arc<dyn DataSource>)
    }
}

#[tokio::test]
async fn cached_statement_execution_routes_through_the_pipeline() {
    let events = RecordingEvents::new();
    let secrets = MemorySecrets::new();
    secrets.register("dsc1");
    let secrets_dyn: Arc<dyn SecretsStore> = secrets;
    let events_dyn: Arc<dyn ConnectionEvents> = events.clone();
    let app = App::new(secrets_dyn, events_dyn);

    let calls = Arc::new(AtomicUsize::new(0));
    let rollbacks = Arc::new(AtomicUsize::new(0));
    app.add_container(
        Arc::new(CachedDriver {
            descriptor: DriverDescriptor::new("fake-cached", "Fake Cached", true),
            calls: calls.clone(),
            rollbacks: rollbacks.clone(),
        }),
        "dsc1",
        ConnectionProperties::new("cached://host/db"),
        vec![],
    );

    app.connect("dsc1").await.expect("connect ok");

    // Aborted first attempt -> rollback -> retry through the cached path.
    let result = app
        .execute_cached_statement_typed("dsc1", "SELECT $1", &[QueryParameter::Integer(9)])
        .await
        .expect("cached statement must recover");
    assert_eq!(result.rows, vec![vec![Some(TypedValue::Int8(9))]]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(rollbacks.load(Ordering::SeqCst), 1);

    app.shutdown().await;
}

// ---------- Transactions-scope invalidation runs a live rollback ----------

/// Data source counting every live ROLLBACK the invalidation bridge issues.
struct CountingRollbackSource {
    counter: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl DataSource for CountingRollbackSource {
    fn metadata(&self) -> DataSourceMetadata {
        DataSourceMetadata {
            product_name: "Fake".into(),
            product_version: "0".into(),
            driver_name: "fake-rollback".into(),
        }
    }

    async fn ping(&self) -> ConnectionResult<()> {
        Ok(())
    }

    async fn rollback_transaction(&self) -> ConnectionResult<()> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn close(&self) {}
}

/// The classified driver, but its data source counts live rollbacks.
struct RollbackDriver {
    descriptor: DriverDescriptor,
    counter: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Driver for RollbackDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    fn error_classifier(&self) -> Option<Arc<dyn ErrorClassifier>> {
        Some(Arc::new(SqlstateClassifier))
    }

    async fn open_data_source(
        &self,
        _request: OpenRequest,
    ) -> ConnectionResult<Arc<dyn DataSource>> {
        Ok(Arc::new(CountingRollbackSource {
            counter: self.counter.clone(),
        }) as Arc<dyn DataSource>)
    }
}

// ---------- typed statement execution through the pipeline ----------

/// Data source with a typed catalog behavior: the first typed execution
/// fails with 25P02, the rest succeed with typed rows; rollbacks counted.
struct TypedEchoSource {
    calls: Arc<AtomicUsize>,
    rollbacks: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl DataSource for TypedEchoSource {
    fn metadata(&self) -> DataSourceMetadata {
        DataSourceMetadata {
            product_name: "Fake".into(),
            product_version: "0".into(),
            driver_name: "fake-typed".into(),
        }
    }

    async fn ping(&self) -> ConnectionResult<()> {
        Ok(())
    }

    async fn rollback_transaction(&self) -> ConnectionResult<()> {
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn execute_statement_typed(
        &self,
        _sql: &str,
        _params: &[QueryParameter],
    ) -> ConnectionResult<TypedStatementResult> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            return Err(ConnectionError::ExecutionFailed {
                sqlstate: Some("25P02".to_owned()),
                message: "current transaction is aborted".into(),
            });
        }
        Ok(TypedStatementResult {
            columns: vec!["n".into()],
            rows: vec![vec![Some(TypedValue::Int8(7))]],
            command_tag: Some("SELECT 1".into()),
            affected_rows: Some(1),
        })
    }

    async fn close(&self) {}
}

/// Classified driver exposing the typed counting data source.
struct TypedDriver {
    descriptor: DriverDescriptor,
    calls: Arc<AtomicUsize>,
    rollbacks: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Driver for TypedDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    fn error_classifier(&self) -> Option<Arc<dyn ErrorClassifier>> {
        Some(Arc::new(SqlstateClassifier))
    }

    async fn open_data_source(
        &self,
        _request: OpenRequest,
    ) -> ConnectionResult<Arc<dyn DataSource>> {
        Ok(Arc::new(TypedEchoSource {
            calls: self.calls.clone(),
            rollbacks: self.rollbacks.clone(),
        }) as Arc<dyn DataSource>)
    }
}

#[tokio::test]
async fn typed_statement_execution_runs_inside_the_recovery_pipeline() {
    let events = RecordingEvents::new();
    let secrets = MemorySecrets::new();
    secrets.register("dst1");
    let secrets_dyn: Arc<dyn SecretsStore> = secrets;
    let events_dyn: Arc<dyn ConnectionEvents> = events.clone();
    let app = App::new(secrets_dyn, events_dyn);

    let calls = Arc::new(AtomicUsize::new(0));
    let rollbacks = Arc::new(AtomicUsize::new(0));
    app.add_container(
        Arc::new(TypedDriver {
            descriptor: DriverDescriptor::new("fake-typed", "Fake Typed", true),
            calls: calls.clone(),
            rollbacks: rollbacks.clone(),
        }),
        "dst1",
        ConnectionProperties::new("typed://host/db"),
        vec![],
    );

    app.connect("dst1").await.expect("connect ok");

    // First attempt aborts (25P02 -> TransactionAborted): the pipeline
    // rolls the live transaction back through the invalidator and retries,
    // returning typed rows from the successful attempt.
    let result = app
        .execute_statement_typed("dst1", "SELECT $1", &[QueryParameter::Integer(7)])
        .await
        .expect("typed statement must recover");
    assert_eq!(
        result.columns,
        vec!["n".to_owned()],
        "typed columns surface at the App level"
    );
    assert_eq!(result.rows, vec![vec![Some(TypedValue::Int8(7))]]);
    assert_eq!(result.command_tag.as_deref(), Some("SELECT 1"));

    assert_eq!(calls.load(Ordering::SeqCst), 2, "one retry after the abort");
    assert_eq!(
        rollbacks.load(Ordering::SeqCst),
        1,
        "the abort invalidation rolled the live transaction back once"
    );

    app.shutdown().await;
}

#[tokio::test]
async fn aborted_transaction_recovery_rolls_back_the_live_connection() {
    let events = RecordingEvents::new();
    let secrets = MemorySecrets::new();
    secrets.register("dsr2");
    let secrets_dyn: Arc<dyn SecretsStore> = secrets;
    let events_dyn: Arc<dyn ConnectionEvents> = events.clone();
    let app = App::new(secrets_dyn, events_dyn);

    let counter = Arc::new(AtomicUsize::new(0));
    app.add_container(
        Arc::new(RollbackDriver {
            descriptor: DriverDescriptor::new("fake-rollback", "Fake Rollback", true),
            counter: counter.clone(),
        }),
        "dsr2",
        ConnectionProperties::new("rollback://host/db"),
        vec![],
    );

    app.connect("dsr2").await.expect("connect ok");

    // 25P02 -> TransactionAborted -> Transactions-scope invalidation, which
    // now executes a live ROLLBACK on the data source before the retry.
    let (result, attempts) = run_state_sequence(&app, "dsr2", "25P02", "42601", 1).await;
    assert!(result.is_ok(), "the aborted statement must be retried");
    assert_eq!(attempts, 2);
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the invalidation must roll back the live connection exactly once"
    );

    let snapshot = events.entries.lock().await.clone();
    assert!(snapshot.contains(&"dsr2:InvalidatedTransaction".to_string()));

    app.shutdown().await;
}
