//! Bounded recovery loop semantics (evidence digest 4.1).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::support::*;
use anydb_shared::ConnectionError;

fn failure_by_attempt(
    failures: usize,
) -> (
    impl FnMut() -> std::future::Ready<Result<(), ConnectionError>>,
    Arc<AtomicUsize>,
) {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let operation = move || {
        let attempt = counter.fetch_add(1, Ordering::SeqCst);
        if attempt < failures {
            std::future::ready(Err(ConnectionError::NetworkFailure))
        } else {
            std::future::ready(Ok(()))
        }
    };
    (operation, attempts)
}

#[tokio::test]
async fn recovers_transaction_aborted_until_success() {
    let invalidator = CountingInvalidator::new();
    let classifier = ThresholdClassifier::new(usize::MAX);
    let runner = anydb_connections::execution::application::commands::execute_with_recovery::RecoveryRunner {
        container_id: "ds1".into(),
        policy: RecoveryPolicy { enabled: true, max_retries: 3 },
        classifier,
        invalidator: invalidator.clone(),
    };
    let (operation, attempts) = failure_by_attempt(2);
    let mut state = RecoveryState::new();

    let outcome = runner.run(&mut state, operation).await;
    assert!(outcome.is_ok());
    assert!(!state.failed);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert_eq!(invalidator.total(), 2);
    assert_eq!(invalidator.scopes(), vec![RecoveryScope::DataSource; 2]);
}

#[tokio::test]
async fn non_recoverable_errors_break_immediately() {
    let invalidator = CountingInvalidator::new();
    let classifier = ThresholdClassifier::new(0); // classify Normal
    let runner = anydb_connections::execution::application::commands::execute_with_recovery::RecoveryRunner {
        container_id: "ds1".into(),
        policy: RecoveryPolicy { enabled: true, max_retries: 3 },
        classifier,
        invalidator: invalidator.clone(),
    };
    let (operation, attempts) = failure_by_attempt(usize::MAX);
    let mut state = RecoveryState::new();

    let outcome = runner.run(&mut state, operation).await;
    assert_eq!(outcome.err(), Some(ConnectionError::NetworkFailure));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(invalidator.total(), 0);
    assert!(state.failed);
}

#[tokio::test]
async fn disabled_policy_never_retries() {
    let invalidator = CountingInvalidator::new();
    let classifier = ThresholdClassifier::new(usize::MAX);
    let runner = anydb_connections::execution::application::commands::execute_with_recovery::RecoveryRunner {
        container_id: "ds1".into(),
        policy: RecoveryPolicy { enabled: false, max_retries: 3 },
        classifier,
        invalidator: invalidator.clone(),
    };
    let (operation, attempts) = failure_by_attempt(usize::MAX);
    let mut state = RecoveryState::new();

    let outcome = runner.run(&mut state, operation).await;
    assert_eq!(outcome.err(), Some(ConnectionError::NetworkFailure));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(invalidator.total(), 0);
    assert!(state.failed);
}

#[tokio::test]
async fn sticky_failed_state_prevents_recovery_next_run() {
    let invalidator = CountingInvalidator::new();
    let classifier = ThresholdClassifier::new(usize::MAX);
    let runner = anydb_connections::execution::application::commands::execute_with_recovery::RecoveryRunner {
        container_id: "ds1".into(),
        policy: RecoveryPolicy { enabled: true, max_retries: 2 },
        classifier,
        invalidator: invalidator.clone(),
    };
    let mut state = RecoveryState::new();

    // Run 1: 3 attempts, 2 invalidations, ends failed.
    let (first, attempts1) = failure_by_attempt(usize::MAX);
    let outcome = runner.run(&mut state, first).await;
    assert_eq!(outcome.err(), Some(ConnectionError::NetworkFailure));
    assert_eq!(attempts1.load(Ordering::SeqCst), 3);
    assert_eq!(invalidator.total(), 2);
    assert!(state.failed);

    // Run 2 with the same state: single attempt, no invalidation.
    let (second, attempts2) = failure_by_attempt(usize::MAX);
    let outcome = runner.run(&mut state, second).await;
    assert_eq!(outcome.err(), Some(ConnectionError::NetworkFailure));
    assert_eq!(attempts2.load(Ordering::SeqCst), 1);
    assert_eq!(invalidator.total(), 2);
}
