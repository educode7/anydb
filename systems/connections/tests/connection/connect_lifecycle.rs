//! Connect pipeline happy path and refusal states (idempotent by state).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anydb_connections::connection::domain::entities::data_source_container::{
    ContainerConfig, ContainerState,
};
use anydb_connections::connection::domain::value_objects::container_status::ContainerStatus;
use anydb_shared::ConnectionError;
use anydb_shared::driver::io::ConnectionProperties;

use crate::support::*;

#[tokio::test]
async fn connect_pipeline_connects_and_applies_stages() {
    let module = module_with_secrets(ScriptedSecrets::ok());
    let (driver, opens) = OkDriver::new(true);
    let tunnel_applies = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let container = ContainerState::new(
        "ds1",
        driver,
        ContainerConfig {
            properties: ConnectionProperties::new("fake://host/db"),
            handlers: vec![Arc::new(TunnelHandler {
                applied: tunnel_applies.clone(),
            })],
        },
    );
    module.add_container(container.clone());

    let status_before = container.status();
    assert_eq!(status_before, ContainerStatus::Disconnected);

    module.connect("ds1").await.expect("connect must succeed");

    assert_eq!(container.status(), ContainerStatus::Connected);
    assert_eq!(opens.load(Ordering::SeqCst), 1);
    assert_eq!(tunnel_applies.load(Ordering::SeqCst), 1);
    let props = container.properties();
    assert_eq!(
        props.settings.get("via").map(String::as_str),
        Some("tunnel")
    );
}

#[tokio::test]
async fn second_connect_is_refused() {
    let module = module_with_secrets(ScriptedSecrets::ok());
    let (driver, _opens) = OkDriver::new(true);
    module.add_container(ContainerState::new(
        "ds1",
        driver,
        ContainerConfig {
            properties: ConnectionProperties::new("fake://host"),
            handlers: vec![],
        },
    ));

    module.connect("ds1").await.expect("first connect ok");
    let second = module.connect("ds1").await;
    assert_eq!(second.err(), Some(ConnectionError::AlreadyConnected));
}

#[tokio::test]
async fn driver_failure_fails_and_keeps_container_reconnectable() {
    let module = module_with_secrets(ScriptedSecrets::ok());
    let driver = FailingDriver::new();
    module.add_container(ContainerState::new(
        "ds1",
        driver,
        ContainerConfig {
            properties: ConnectionProperties::new("fake://host"),
            handlers: vec![],
        },
    ));

    let outcome = module.connect("ds1").await;
    assert_eq!(outcome.err(), Some(ConnectionError::DriverFailure));

    let status = module.status("ds1").expect("query status");
    assert_eq!(status.status, "failed");

    // DBeaver semantics: a failed data source is retryable.
    assert_ne!(
        module.connect("ds1").await.err(),
        Some(ConnectionError::AlreadyConnected)
    );
}

#[tokio::test]
async fn missing_secrets_fail_the_pipeline() {
    let module = module_with_secrets(ScriptedSecrets::failing());
    let (driver, _opens) = OkDriver::new(true);
    module.add_container(ContainerState::new(
        "ds1",
        driver,
        ContainerConfig {
            properties: ConnectionProperties::new("fake://host"),
            handlers: vec![],
        },
    ));

    let outcome = module.connect("ds1").await;
    assert_eq!(outcome.err(), Some(ConnectionError::MissingSecrets));
}

#[tokio::test]
async fn disconnect_closes_data_source_and_renames_status() {
    let module = module_with_secrets(ScriptedSecrets::ok());
    let (driver, opens) = OkDriver::new(true);
    module.add_container(ContainerState::new(
        "ds1",
        driver,
        ContainerConfig {
            properties: ConnectionProperties::new("fake://host"),
            handlers: vec![],
        },
    ));

    module.connect("ds1").await.expect("connect ok");
    assert_eq!(opens.load(Ordering::SeqCst), 1);

    module.disconnect("ds1").await.expect("disconnect ok");
    let container = module.container("ds1").expect("container");
    assert_eq!(container.status(), ContainerStatus::Disconnected);

    // Reconnect allowed after disconnect.
    module.connect("ds1").await.expect("reconnect ok");
    assert_eq!(opens.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unknown_container_is_reported() {
    let module = module_with_secrets(ScriptedSecrets::ok());
    assert_eq!(
        module.connect("nope").await.err(),
        Some(ConnectionError::ContainerNotFound)
    );
}
