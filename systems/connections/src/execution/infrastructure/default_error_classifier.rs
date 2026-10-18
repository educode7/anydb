//! Default classifier: the shared kernel's conservative mapping.

use anydb_shared::{ConnectionError, ErrorType};

use crate::execution::domain::ports::error_classifier::ErrorClassifier;

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultErrorClassifier;

impl ErrorClassifier for DefaultErrorClassifier {
    fn classify(&self, error: &ConnectionError) -> ErrorType {
        ErrorType::default_classify(error)
    }
}
