//! Error classification contract (DBeaver driver `DBPErrorAssistant` /
//! `discoverErrorType` override analog): drivers that decode native error
//! payloads supply a classifier; `None` selects the shared kernel's
//! conservative mapping (`ErrorType::default_classify`).

use std::sync::Arc;

use crate::ConnectionError;
use crate::ErrorType;

/// Sync by design: classification is cheap and must not suspend.
pub trait ErrorClassifier: Send + Sync {
    fn classify(&self, error: &ConnectionError) -> ErrorType;
}

/// Kernel-default implementation, mirroring the connections system's
/// `DefaultErrorClassifier`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultClassifier;

impl ErrorClassifier for DefaultClassifier {
    fn classify(&self, error: &ConnectionError) -> ErrorType {
        ErrorType::default_classify(error)
    }
}

/// Resolves the effective classifier for a driver (DBeaver
/// `errorTypeAssistant` selection analog).
pub fn effective_classifier(
    driver_override: Option<Arc<dyn ErrorClassifier>>,
) -> Arc<dyn ErrorClassifier> {
    driver_override.unwrap_or_else(|| Arc::new(DefaultClassifier))
}
