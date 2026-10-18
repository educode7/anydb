//! Fakes for execution tests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

pub use anydb_connections::execution::domain::ports::error_classifier::ErrorClassifier;
pub use anydb_connections::execution::domain::ports::invalidation_target::InvalidationTarget;
pub use anydb_connections::execution::domain::value_objects::recovery_policy::RecoveryPolicy;
pub use anydb_connections::execution::domain::value_objects::recovery_state::RecoveryState;
pub use anydb_connections::execution::domain::value_objects::statement_gate::StatementGate;
pub use anydb_shared::{ConnectionError, ErrorType, RecoveryScope};

pub struct CountingInvalidator {
    pub calls: Mutex<Vec<RecoveryScope>>,
}

impl CountingInvalidator {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
        })
    }

    pub fn total(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    pub fn scopes(&self) -> Vec<RecoveryScope> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl InvalidationTarget for CountingInvalidator {
    async fn invalidate(
        &self,
        scope: RecoveryScope,
        _container_id: &str,
    ) -> Result<(), ConnectionError> {
        self.calls.lock().unwrap().push(scope);
        Ok(())
    }
}

/// Classifies the first `network_failures` errors as `ConnectionLost`, the
/// following ones as `Normal`.
pub struct ThresholdClassifier {
    pub network_failures: AtomicUsize,
}

impl ThresholdClassifier {
    pub fn new(network_failures: usize) -> Arc<Self> {
        Arc::new(Self {
            network_failures: AtomicUsize::new(network_failures),
        })
    }
}

impl ErrorClassifier for ThresholdClassifier {
    fn classify(&self, _error: &ConnectionError) -> ErrorType {
        let remaining = self.network_failures.fetch_sub(1, Ordering::SeqCst);
        if remaining > 0 {
            ErrorType::ConnectionLost
        } else {
            ErrorType::Normal
        }
    }
}
