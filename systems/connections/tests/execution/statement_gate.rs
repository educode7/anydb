//! Statement gate semantics (evidence digest 4.2). The serialized gate
//! exclusion check uses tokio's paused-time tests: deterministic, no sleeps.

use anydb_shared::driver::descriptor::DriverDescriptor;

use crate::support::*;

#[tokio::test(start_paused = true)]
async fn thread_safe_driver_gets_unprotected_gate() {
    let descriptor = DriverDescriptor::new("fake", "Fake", true);
    let gate = StatementGate::for_driver(&descriptor);
    let ticket = gate.acquire().await.expect("acquire ok");
    assert!(!ticket.is_active());
}

#[tokio::test(start_paused = true)]
async fn serialized_gate_blocks_second_holder() {
    let descriptor = DriverDescriptor::new("fake", "Fake", false);
    let gate = StatementGate::for_driver(&descriptor);

    let first = gate.acquire().await.expect("first acquire ok");
    assert!(first.is_active());

    let waiter = tokio::spawn({
        let gate = gate.clone();
        async move { gate.acquire().await }
    });

    // Polled once: still blocked while the first ticket is held.
    tokio::task::yield_now().await;
    assert!(
        !waiter.is_finished(),
        "second holder must remain blocked while first holds the gate"
    );

    drop(first);
    let second = waiter
        .await
        .expect("waiter completes")
        .expect("acquire after release");
    assert!(second.is_active());
}
