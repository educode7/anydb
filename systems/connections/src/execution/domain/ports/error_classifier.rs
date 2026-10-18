//! Error type classifier port (DBeaver driver `DBPErrorAssistant` analog).

use anydb_shared::{ConnectionError, ErrorType};

/// Sync by design: classification is cheap and must not suspend.
pub trait ErrorClassifier: Send + Sync {
    fn classify(&self, error: &ConnectionError) -> ErrorType;
}
