//! UI/async bridge: iced owns the main thread; the platform `App` runs on a
//! tokio runtime inside ONE background worker thread. The UI sends
//! [`Command`]s over a std channel and drains [`Event`]s every frame.
//!
//! [`spawn`] is the supported entry point: it builds the [`App`] inside the
//! worker's own runtime context (the job queue spawns onto the current
//! runtime at construction) and returns the two channel halves plus the join
//! handle. Driver selection is a [`DriverFactory`] the caller supplies.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, RwLock};

use anydb::prelude::ConnectionEventKind;
use anydb::prelude::{
    App, ConnectionError, ConnectionEvents, ConnectionProperties, Driver, TypedStatementResult,
};

/// Ephemeral secrets store: resolves an empty map for any container. V1
/// carries credentials in the target URL (mirroring the real drivers), so the
/// connect pipeline's unconditional secret resolution never aborts.
#[derive(Debug, Default)]
struct EphemeralSecrets {
    entries: RwLock<HashMap<String, HashMap<String, String>>>,
}

#[async_trait::async_trait]
impl anydb::prelude::SecretsStore for EphemeralSecrets {
    async fn resolve(
        &self,
        container_id: &str,
    ) -> Result<HashMap<String, String>, ConnectionError> {
        Ok(self
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(container_id)
            .cloned()
            .unwrap_or_default())
    }
}

/// Bridge from the platform's connection lifecycle events into the worker ->
/// UI event channel. The UI never touches a driver; it observes these.
struct EventSink {
    sender: Sender<Event>,
}

#[async_trait::async_trait]
impl ConnectionEvents for EventSink {
    async fn on_event(&self, container_id: &str, kind: ConnectionEventKind) {
        let text = match kind {
            ConnectionEventKind::BeforeConnect => "connecting",
            ConnectionEventKind::AfterConnect => "connected",
            ConnectionEventKind::AfterDisconnect => "disconnected",
            ConnectionEventKind::InvalidatedTransaction => "transaction invalidated",
            ConnectionEventKind::InvalidatedDataSource => "data source invalidated",
        };
        let _ = self
            .sender
            .send(Event::StatusChanged(format!("{container_id}: {text}")));
    }
}

/// Produces a driver for a target URL. Production supplies the real postgres
/// and mongo drivers keyed by URL scheme; tests supply a fake.
pub type DriverFactory = Arc<dyn Fn(&str) -> Option<Arc<dyn Driver>> + Send + Sync>;

/// Container id registered on the `App` for the single live connection.
/// A `Connect` always targets this id (V1: one connection at a time).
pub const CONTAINER_ID: &str = "desktop";

/// UI -> worker commands. `Connect` carries the raw target URL; the factory
/// picks the driver for its scheme.
#[derive(Debug, Clone)]
pub enum Command {
    Connect { url: String },
    Disconnect,
    Status,
    Execute { sql: String },
    Shutdown,
}

/// Worker -> UI events. `ResultReady` carries the typed result verbatim so
/// the grid renders columns/rows/command tag without re-decoding.
#[derive(Debug, Clone)]
pub enum Event {
    Connected,
    Disconnected,
    StatusChanged(String),
    ExecutionFailed(String),
    ResultReady(TypedStatementResult),
}

/// Builds the platform [`App`] and spawns [`run_loop`] on a dedicated worker
/// thread. The `App` must be constructed *inside* the thread's tokio runtime
/// context (its job queue spawns onto the current runtime at construction).
/// Returns the command sender, the event receiver, and the join handle.
pub fn spawn(
    factory: DriverFactory,
) -> (
    Sender<Command>,
    Receiver<Event>,
    std::thread::JoinHandle<()>,
) {
    let (command_tx, command_rx) = std::sync::mpsc::channel();
    let (event_tx, event_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        // Enter the runtime context BEFORE building the `App`: its job queue
        // spawns onto the current runtime at construction, which needs an
        // active context. The guard drops so `block_on` can drive the loop.
        let _guard = runtime.enter();
        let app = App::new(
            Arc::new(EphemeralSecrets::default()),
            Arc::new(EventSink {
                sender: event_tx.clone(),
            }),
        );
        drop(_guard);
        runtime.block_on(run_loop(app, factory, &command_rx, &event_tx));
    });
    (command_tx, event_rx, handle)
}

/// Drives one [`App`] from the [`Command`] stream until `Shutdown` or until
/// the UI drops the command sender. Runs inside the worker's tokio runtime
/// context; the UI thread never blocks on any of this.
pub async fn run_loop(
    app: App,
    factory: DriverFactory,
    commands: &Receiver<Command>,
    events: &Sender<Event>,
) {
    while let Ok(command) = commands.recv() {
        match command {
            Command::Connect { url } => match factory(&url) {
                Some(driver) => {
                    app.add_container(
                        driver,
                        CONTAINER_ID,
                        ConnectionProperties::new(url),
                        Vec::new(),
                    );
                    match app.connect(CONTAINER_ID).await {
                        Ok(_) => {
                            let _ = events.send(Event::Connected);
                        }
                        Err(error) => {
                            let _ = events.send(Event::ExecutionFailed(error.to_string()));
                        }
                    }
                }
                None => {
                    let _ = events.send(Event::ExecutionFailed(format!(
                        "no driver for target scheme: {url}"
                    )));
                }
            },
            Command::Disconnect => {
                let _ = app.disconnect(CONTAINER_ID).await;
                let _ = events.send(Event::Disconnected);
            }
            Command::Status => {
                let text = app
                    .status(CONTAINER_ID)
                    .map(|dto| dto.status)
                    .unwrap_or_else(|_| "disconnected".to_owned());
                let _ = events.send(Event::StatusChanged(text));
            }
            Command::Execute { sql } => {
                let result = app.execute_statement_typed(CONTAINER_ID, &sql, &[]).await;
                match result {
                    Ok(typed) => {
                        let _ = events.send(Event::ResultReady(typed));
                    }
                    Err(error) => {
                        let _ = events.send(Event::ExecutionFailed(error.to_string()));
                    }
                }
            }
            Command::Shutdown => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use anydb::prelude::ConnectionResult;

    use anydb::prelude::{
        DataSource, DataSourceMetadata, DriverDescriptor, OpenRequest, TypedValue,
    };

    /// Generous upper bound so a hang surfaces as a failure, not a stuck test.
    const TIMEOUT: Duration = Duration::from_secs(5);

    /// Fake data source returning one row and recording the executed SQL.
    struct FakeSource {
        sql_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl DataSource for FakeSource {
        fn metadata(&self) -> DataSourceMetadata {
            DataSourceMetadata {
                product_name: "fake".to_owned(),
                product_version: "0".to_owned(),
                driver_name: "fake".to_owned(),
            }
        }

        async fn ping(&self) -> ConnectionResult<()> {
            Ok(())
        }

        async fn execute_statement_typed(
            &self,
            _sql: &str,
            _params: &[anydb::prelude::QueryParameter],
        ) -> ConnectionResult<TypedStatementResult> {
            self.sql_calls.fetch_add(1, Ordering::SeqCst);
            Ok(TypedStatementResult {
                columns: vec!["n".into()],
                rows: vec![vec![Some(TypedValue::Int8(7))]],
                command_tag: Some("SELECT 1".into()),
                affected_rows: Some(1),
                message: None,
            })
        }

        async fn close(&self) {}
    }

    struct FakeDriver {
        descriptor: DriverDescriptor,
        sql_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Driver for FakeDriver {
        fn descriptor(&self) -> &DriverDescriptor {
            &self.descriptor
        }

        async fn open_data_source(
            &self,
            _request: OpenRequest,
        ) -> ConnectionResult<Arc<dyn DataSource>> {
            Ok(Arc::new(FakeSource {
                sql_calls: self.sql_calls.clone(),
            }))
        }
    }

    /// Spawns a bridge over a fake factory that only knows `fake://`. Returns
    /// the command sender, the event receiver, the call counter, and the
    /// worker join handle.
    fn spawn_bridge() -> (
        Sender<Command>,
        Receiver<Event>,
        Arc<AtomicUsize>,
        std::thread::JoinHandle<()>,
    ) {
        let sql_calls = Arc::new(AtomicUsize::new(0));
        let counter = sql_calls.clone();
        let factory: DriverFactory = Arc::new(move |url: &str| {
            if url.starts_with("fake://") {
                let driver: Arc<dyn Driver> = Arc::new(FakeDriver {
                    descriptor: DriverDescriptor::new("fake", "Fake", true),
                    sql_calls: counter.clone(),
                });
                Some(driver)
            } else {
                None
            }
        });
        let (commands, events, worker) = spawn(factory);
        (commands, events, sql_calls, worker)
    }

    /// Drains events until `predicate` matches one, returning it. Panics if
    /// nothing matches within the timeout (surfaces a hang as a failure).
    fn recv_matching(
        events: &Receiver<Event>,
        what: &str,
        predicate: impl Fn(&Event) -> bool,
    ) -> Event {
        let deadline = std::time::Instant::now() + TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match events.recv_timeout(remaining) {
                Ok(event) if predicate(&event) => return event,
                Ok(_) => continue,
                Err(_) => panic!("timed out waiting for {what}"),
            }
        }
    }

    #[test]
    fn connect_then_execute_delivers_connected_then_result() {
        let (commands, events, sql_calls, worker) = spawn_bridge();

        commands
            .send(Command::Connect {
                url: "fake://db".to_owned(),
            })
            .expect("send connect");
        // The bridge's contract (S2): `Connect` resolves to `Connected`. The
        // lifecycle sink may interleave extra status events; those are
        // covered by their own test, so here we only require the command
        // outcome.
        recv_matching(&events, "Connected", |e| matches!(e, Event::Connected));

        commands
            .send(Command::Execute {
                sql: "SELECT 1".to_owned(),
            })
            .expect("send execute");
        match recv_matching(&events, "ResultReady", |e| {
            matches!(e, Event::ResultReady(_))
        }) {
            Event::ResultReady(result) => {
                assert_eq!(result.columns, vec!["n".to_owned()]);
                assert_eq!(result.rows, vec![vec![Some(TypedValue::Int8(7))]]);
                assert_eq!(result.command_tag.as_deref(), Some("SELECT 1"));
            }
            other => panic!("expected ResultReady, got {other:?}"),
        }
        // The typed path really reached the driver.
        assert_eq!(sql_calls.load(Ordering::SeqCst), 1);

        commands.send(Command::Shutdown).expect("send shutdown");
        worker.join().expect("worker joins");
    }

    #[test]
    fn connect_with_unknown_scheme_fails_before_any_driver() {
        let (commands, events, sql_calls, worker) = spawn_bridge();

        commands
            .send(Command::Connect {
                url: "oracle://db".to_owned(),
            })
            .expect("send connect");
        match recv_matching(&events, "ExecutionFailed", |e| {
            matches!(e, Event::ExecutionFailed(_))
        }) {
            Event::ExecutionFailed(message) => assert!(message.contains("no driver")),
            other => panic!("expected ExecutionFailed, got {other:?}"),
        }
        // The factory rejected the scheme: no driver, no wire.
        assert_eq!(sql_calls.load(Ordering::SeqCst), 0);

        commands.send(Command::Shutdown).expect("send shutdown");
        worker.join().expect("worker joins");
    }

    #[test]
    fn disconnect_and_status_route_their_events() {
        let (commands, events, _sql_calls, worker) = spawn_bridge();

        commands.send(Command::Disconnect).expect("send disconnect");
        recv_matching(&events, "Disconnected", |e| {
            matches!(e, Event::Disconnected)
        });

        commands.send(Command::Status).expect("send status");
        match recv_matching(&events, "StatusChanged", |e| {
            matches!(e, Event::StatusChanged(_))
        }) {
            Event::StatusChanged(text) => assert_eq!(text, "disconnected"),
            other => panic!("expected StatusChanged, got {other:?}"),
        }

        commands.send(Command::Shutdown).expect("send shutdown");
        worker.join().expect("worker joins");
    }

    #[test]
    fn execute_before_connect_reports_an_error_event() {
        let (commands, events, sql_calls, worker) = spawn_bridge();

        commands
            .send(Command::Execute {
                sql: "SELECT 1".to_owned(),
            })
            .expect("send execute");
        match recv_matching(&events, "ExecutionFailed", |e| {
            matches!(e, Event::ExecutionFailed(_))
        }) {
            Event::ExecutionFailed(message) => assert!(!message.is_empty()),
            other => panic!("expected ExecutionFailed, got {other:?}"),
        }
        // Failure is client-side (no live data source): the wire was never
        // reached.
        assert_eq!(sql_calls.load(Ordering::SeqCst), 0);

        commands.send(Command::Shutdown).expect("send shutdown");
        worker.join().expect("worker joins");
    }

    #[test]
    fn shutdown_terminates_the_loop() {
        let (commands, events, _sql_calls, worker) = spawn_bridge();
        commands.send(Command::Shutdown).expect("send shutdown");
        worker.join().expect("worker joins cleanly");
        // Sender is still alive here, so the channel is open: the loop
        // exited on `Shutdown`, not on a closed channel.
        assert!(events.try_recv().is_err());
    }
}
