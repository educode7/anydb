//! Bounded recovery runner (evidence digest 4.1): classify -> invalidate ->
//! retry, with a sticky `failed` flag preventing retry storms.

use std::future::Future;
use std::sync::Arc;

use anydb_shared::ConnectionError;

use crate::execution::domain::ports::error_classifier::ErrorClassifier;
use crate::execution::domain::ports::invalidation_target::InvalidationTarget;
use crate::execution::domain::value_objects::recovery_policy::RecoveryPolicy;
use crate::execution::domain::value_objects::recovery_state::RecoveryState;

pub struct RecoveryRunner {
    pub container_id: String,
    pub policy: RecoveryPolicy,
    pub classifier: Arc<dyn ErrorClassifier>,
    pub invalidator: Arc<dyn InvalidationTarget>,
}

impl RecoveryRunner {
    /// Runs `operation`, retrying only on recoverable error classes
    /// (`TRANSACTION_ABORTED` / `CONNECTION_LOST`), invalidating the matching
    /// scope between attempts. Mirrors `DBExecUtils.tryExecuteRecover`:
    /// nested runs (depth > 0) or a previously-failed run do not retry.
    pub async fn run<T, Fut, F>(
        &self,
        state: &mut RecoveryState,
        mut operation: F,
    ) -> Result<T, ConnectionError>
    where
        Fut: Future<Output = Result<T, ConnectionError>> + Send,
        F: FnMut() -> Fut,
    {
        state.depth += 1;
        let mut result: Result<T, ConnectionError> = Err(ConnectionError::Canceled);
        let recover_enabled = self.policy.enabled && !state.failed;
        let try_count = if recover_enabled {
            1 + self.policy.max_retries
        } else {
            1
        };

        for attempt_no in 0..try_count {
            match operation().await {
                Ok(value) => {
                    result = Ok(value);
                    break;
                }
                Err(error) => {
                    let error_type = self.classifier.classify(&error);
                    // DBeaver invalidates only *between* attempts: the final
                    // failed attempt propagates without a last invalidation.
                    let has_next_attempt = attempt_no + 1 < try_count;
                    match error_type.recovery_scope() {
                        Some(scope) if recover_enabled && has_next_attempt => {
                            let _ = self.invalidator.invalidate(scope, &self.container_id).await;
                            result = Err(error);
                        }
                        _ => {
                            result = Err(error);
                            break;
                        }
                    }
                }
            }
        }

        if result.is_err() {
            state.failed = true;
        }
        state.depth -= 1;
        result
    }
}
