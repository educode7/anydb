//! Supervised keepalive loop semantics (DBeaver `KeepAlivePingJob` analog),
//! under tokio paused time: deterministic, no sleeps.

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::task::JoinSet;

use anydb_connections::connection::domain::entities::data_source_container::{
    ContainerConfig, ContainerState,
};
use anydb_connections::connection::domain::value_objects::container_status::ContainerStatus;
use anydb_connections::connection::infrastructure::monitor::{
    KeepAliveLoopConfig, spawn_keepalive_loop,
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
