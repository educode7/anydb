//! Supervised keepalive loop semantics (DBeaver `KeepAlivePingJob` analog),
//! under tokio paused time: deterministic, no sleeps.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::task::JoinSet;

use anydb_connections::connection::api::ConnectionModule;
use anydb_connections::connection::domain::entities::data_source_container::{
    ContainerConfig, ContainerState,
};
use anydb_connections::connection::domain::value_objects::container_status::ContainerStatus;
use anydb_connections::connection::infrastructure::job_queue::BoundJobQueue;
use anydb_connections::connection::infrastructure::monitor::{
    KeepAliveLoopConfig, MonitorLoopConfig, spawn_keepalive_loop, spawn_monitor_loop,
};
use anydb_shared::driver::io::ConnectionProperties;

use crate::support::*;
fn sweep_config() -> KeepAliveLoopConfig {
    KeepAliveLoopConfig {
        interval: Duration::from_millis(10),
        ping_timeout: Duration::from_secs(1),
    }
}

#[tokio::test(start_paused = true)]
async fn keepalive_pings_connected_containers_repeatedly() {
    let module = module_with_secrets(ScriptedSecrets::ok());
    let (driver, opens, pings) = PingDriver::new(false);
    module.add_container(ContainerState::new(
        "ds1",
        driver,
        ContainerConfig {
            properties: ConnectionProperties::new("ping://host"),
            handlers: vec![],
        },
    ));
    module.connect("ds1").await.expect("connect ok");

    let mut tasks = JoinSet::new();
    // Keep the handle alive: dropping it cancels the loop. Blocking the test
    // task on a timer lets paused-time auto-advance drive the loop's ticks
    // (tokio 1.53 does not poll side tasks across manual `advance`).
    let _handle = spawn_keepalive_loop(&module, sweep_config(), &mut tasks);
    tokio::time::sleep(Duration::from_millis(55)).await;

    assert_eq!(
        opens.load(Ordering::SeqCst),
        1,
        "exactly one open data source"
    );
    assert!(
        pings.load(Ordering::SeqCst) >= 2,
        "connected container must be swept on every tick"
    );
}

#[tokio::test(start_paused = true)]
async fn failed_ping_invalidates_the_data_source() {
    let module = module_with_secrets(ScriptedSecrets::ok());
    let (driver, _opens, pings) = PingDriver::new(true);
    module.add_container(ContainerState::new(
        "ds1",
        driver,
        ContainerConfig {
            properties: ConnectionProperties::new("ping://host"),
            handlers: vec![],
        },
    ));
    module.connect("ds1").await.expect("connect ok");

    let mut tasks = JoinSet::new();
    let _handle = spawn_keepalive_loop(&module, sweep_config(), &mut tasks);
    tokio::time::sleep(Duration::from_millis(35)).await;

    assert!(
        pings.load(Ordering::SeqCst) >= 1,
        "the sweep must have pinged"
    );
    let container = module.container("ds1").expect("container");
    assert_eq!(
        container.status(),
        ContainerStatus::Disconnected,
        "a failed ping must invalidate the data source"
    );
}

#[tokio::test(start_paused = true)]
async fn cancel_handle_stops_the_sweep() {
    let module = module_with_secrets(ScriptedSecrets::ok());
    let (driver, _opens, pings) = PingDriver::new(false);
    module.add_container(ContainerState::new(
        "ds1",
        driver,
        ContainerConfig {
            properties: ConnectionProperties::new("ping://host"),
            handlers: vec![],
        },
    ));
    module.connect("ds1").await.expect("connect ok");

    let mut tasks = JoinSet::new();
    let handle = spawn_keepalive_loop(&module, sweep_config(), &mut tasks);
    handle.cancel();

    tokio::time::sleep(Duration::from_millis(35)).await;

    assert_eq!(
        pings.load(Ordering::SeqCst),
        0,
        "a cancelled loop must not sweep"
    );
}

// ---------- monitor loop (DBeaver `DataSourceMonitorJob` analog) ----------

fn monitor_config() -> MonitorLoopConfig {
    MonitorLoopConfig {
        interval: Duration::from_millis(10),
        ping_timeout: Duration::from_secs(1),
        reconnect_cooldown: Duration::from_millis(20),
        max_reconnect_attempts: 3,
    }
}

fn event_count(events: &RecordingEvents, entry: &str) -> usize {
    events
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|line| line.ends_with(entry))
        .count()
}

/// Builds a monitor-owned container with a fake driver.
fn auto_container(
    module: &ConnectionModule,
    driver: Arc<dyn Driver>,
    id: &str,
) -> Arc<ContainerState> {
    let container = ContainerState::new(
        id,
        driver,
        ContainerConfig {
            properties: ConnectionProperties::new("monitor://host"),
            handlers: vec![],
        },
    );
    container.set_auto_reconnect(true);
    module.add_container(container.clone());
    container
}

#[tokio::test(start_paused = true)]
async fn monitor_auto_restores_a_dead_source_with_bounded_attempts() {
    let (module, events) = module_with_events();
    let (driver, opens, pings) = PingDriver::new(true);
    auto_container(&module, driver, "ds1");
    module.connect("ds1").await.expect("connect ok");

    let mut tasks = JoinSet::new();
    let executor = ConnectionModule::job_executor(&module);
    let queue = BoundJobQueue::spawn(executor, 32, &mut tasks);
    let _handle = spawn_monitor_loop(&module, &queue, monitor_config(), &mut tasks);

    // 20 ticks are plenty: the attempt cycle settles after ~7 ticks.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        opens.load(Ordering::SeqCst),
        4,
        "the manual connect plus exactly three automatic attempts"
    );
    assert!(
        pings.load(Ordering::SeqCst) >= 4,
        "each connected tick probes"
    );
    assert_eq!(
        event_count(&events, "InvalidatedDataSource"),
        4,
        "every faulty connected-tick ping invalidates"
    );
    assert_eq!(
        event_count(&events, "AfterConnect"),
        4,
        "the manual connect plus the three restored ones"
    );
    assert_eq!(
        module.container("ds1").expect("container").status(),
        ContainerStatus::Disconnected,
        "attempts saturate: the dead source stays invalidated"
    );
}

#[tokio::test(start_paused = true)]
async fn monitor_never_reconnects_a_manually_disconnected_container() {
    let (module, _events) = module_with_events();
    let (driver, opens, _pings) = PingDriver::new(true);
    auto_container(&module, driver, "ds1");
    module.connect("ds1").await.expect("connect ok");
    module.disconnect("ds1").await.expect("disconnect ok");

    let mut tasks = JoinSet::new();
    let executor = ConnectionModule::job_executor(&module);
    let queue = BoundJobQueue::spawn(executor, 32, &mut tasks);
    let _handle = spawn_monitor_loop(&module, &queue, monitor_config(), &mut tasks);

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        opens.load(Ordering::SeqCst),
        1,
        "no automatic reconnect after a user disconnect"
    );
    assert_eq!(
        module.container("ds1").expect("container").status(),
        ContainerStatus::Disconnected
    );
}

#[tokio::test(start_paused = true)]
async fn connect_attempts_wait_for_the_cooldown() {
    let (module, events) = module_with_events();
    let (driver, opens, _pings) = PingDriver::new(true);
    auto_container(&module, driver, "ds1");
    module.connect("ds1").await.expect("connect ok");

    // Cooldown of one second against a 10 ms tick: ~100 ticks of wait.
    let config = MonitorLoopConfig {
        reconnect_cooldown: Duration::from_secs(1),
        ..monitor_config()
    };
    let mut tasks = JoinSet::new();
    let executor = ConnectionModule::job_executor(&module);
    let queue = BoundJobQueue::spawn(executor, 32, &mut tasks);
    let _handle = spawn_monitor_loop(&module, &queue, config, &mut tasks);

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        opens.load(Ordering::SeqCst),
        2,
        "only the first attempt fits inside the cooldown window"
    );
    assert_eq!(
        event_count(&events, "InvalidatedDataSource"),
        2,
        "the second faulty ping invalidates but cannot trigger a new attempt"
    );
    assert_eq!(
        module.container("ds1").expect("container").status(),
        ContainerStatus::Disconnected,
        "no source to keep pinging during the cooldown"
    );
}

#[tokio::test(start_paused = true)]
async fn a_healthy_ping_resets_attempts_and_re_arms_auto_restore() {
    let (module, events) = module_with_events();
    let (driver, opens, _pings, fail) = TogglePingDriver::new();
    auto_container(&module, driver, "ds1");
    module.connect("ds1").await.expect("connect ok");

    let mut tasks = JoinSet::new();
    let executor = ConnectionModule::job_executor(&module);
    let queue = BoundJobQueue::spawn(executor, 32, &mut tasks);
    let _handle = spawn_monitor_loop(&module, &queue, monitor_config(), &mut tasks);

    // Stage 1: failing pings until the attempt cap.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(opens.load(Ordering::SeqCst), 4, "cap reached");
    assert_eq!(
        module.container("ds1").expect("container").status(),
        ContainerStatus::Disconnected,
        "gave up until the next healthy ping"
    );

    // Stage 2: network recovered; the user reconnects and the monitor
    // observes healthy pings, resetting the bookkeeping.
    fail.store(false, Ordering::SeqCst);
    module.connect("ds1").await.expect("manual connect ok");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        module.container("ds1").expect("container").status(),
        ContainerStatus::Connected,
        "healthy pings keep the container connected"
    );

    // Stage 3: dead again: a fresh bounded series runs.
    fail.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        opens.load(Ordering::SeqCst),
        8,
        "3 + 0 (healthy reset) + 1 manual + 3 restored opens"
    );
    assert_eq!(
        event_count(&events, "AfterConnect"),
        8,
        "1 manual + 3 + 1 manual + 3 restored connects"
    );
    assert_eq!(
        event_count(&events, "InvalidatedDataSource"),
        8,
        "two faulty-ping series of four connected-tick invalidations"
    );
}
