//! PostgreSQL SQLSTATE-driven error classification (PostgreSQL docs,
//! Appendix A error codes + DBeaver `DBPErrorAssistant` mapping analog).
//!
//! The recovery loop only acts on `TransactionAborted` (rollback the
//! failed implicit transaction) and `ConnectionLost` (reconnect the data
//! source); `ExecutionCanceled` and `Normal` must not trigger recovery.

use anydb_shared::driver::classification::ErrorClassifier;
use anydb_shared::{ConnectionError, ErrorType};

/// SQLSTATE-driven classifier used as `Driver::error_classifier`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SqlStateClassifier;

impl ErrorClassifier for SqlStateClassifier {
    fn classify(&self, error: &ConnectionError) -> ErrorType {
        match error {
            ConnectionError::ExecutionFailed {
                sqlstate: Some(code),
                ..
            } => classify_sqlstate(code),
            _ => ErrorType::default_classify(error),
        }
    }
}

/// Classifies one `C`-field code. Malformed codes degrade to `Normal`
/// (conservative: no recovery action).
pub fn classify_sqlstate(code: &str) -> ErrorType {
    let Ok(class) = state_class(code) else {
        return ErrorType::Normal;
    };
    match class {
        // Class 08: connection exception (connection_exists, unable to
        // establish, does_not_exist, connection_failure, ...).
        "08" => ErrorType::ConnectionLost,
        // Class 25: invalid transaction state. `in_failed_sql_transaction`
        // is the aborted-transaction signature; the idle-in-transaction
        // timeouts terminate the session instead.
        "25" if code == "25P03" => ErrorType::ConnectionLost,
        "25" => ErrorType::TransactionAborted,
        // Class 40: transaction rollback (serialization failure, deadlock
        // detected, statement_completion_unknown).
        "40" => ErrorType::TransactionAborted,
        // Class 57 operator intervention, in cancellation-first order:
        // 57014 query_canceled (statement_timeout / pg_cancel_backend) is
        // NOT session-terminating; 57P01 admin_shutdown, 57P02
        // crash_shutdown, 57P03 cannot_connect_now and 57P05
        // idle_session_timeout terminate the session.
        "57" if code == "57014" => ErrorType::ExecutionCanceled,
        "57" if matches!(code, "57P01" | "57P02" | "57P03" | "57P05") => ErrorType::ConnectionLost,
        _ => ErrorType::Normal,
    }
}

/// Valid SQLSTATE: 5 chars, `DDDDD` or `DDccc` (two digits + three alnum).
fn state_class(code: &str) -> Result<&str, ()> {
    let bytes = code.as_bytes();
    match bytes {
        [a, b, _, _, _] if a.is_ascii_digit() && b.is_ascii_digit() => Ok(&code[..2]),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_aborted_classes() {
        // 25P02 in_failed_sql_transaction: the key rollback-recovery one.
        assert_eq!(classify_sqlstate("25P02"), ErrorType::TransactionAborted);
        // Session-level idle-in-transaction timeout kills the session.
        assert_eq!(classify_sqlstate("25P03"), ErrorType::ConnectionLost);
        // Class 40: serialization failure / deadlock.
        assert_eq!(classify_sqlstate("40001"), ErrorType::TransactionAborted);
        assert_eq!(classify_sqlstate("40P01"), ErrorType::TransactionAborted);
        assert_eq!(classify_sqlstate("40P03"), ErrorType::TransactionAborted);
    }

    #[test]
    fn connection_lost_classes() {
        // Whole class 08.
        for code in ["08000", "08001", "08003", "08004", "08006", "08007"] {
            assert_eq!(classify_sqlstate(code), ErrorType::ConnectionLost, "{code}");
        }
        // Operator intervention / session-terminating timeouts.
        for code in ["57P01", "57P02", "57P03", "57P05"] {
            assert_eq!(classify_sqlstate(code), ErrorType::ConnectionLost, "{code}");
        }
        // Other class 57 codes are NOT connection: 57014 is a cancellation.
        assert_eq!(classify_sqlstate("57P04"), ErrorType::Normal);
    }

    #[test]
    fn canceled_and_normal_cases() {
        assert_eq!(classify_sqlstate("57014"), ErrorType::ExecutionCanceled);
        // Runtime statements the user must re-think: syntax, undefined
        // objects, integrity violations. No recovery.
        assert_eq!(classify_sqlstate("42601"), ErrorType::Normal);
        assert_eq!(classify_sqlstate("42P10"), ErrorType::Normal);
        assert_eq!(classify_sqlstate("23505"), ErrorType::Normal);
        assert_eq!(classify_sqlstate("00000"), ErrorType::Normal);
    }

    #[test]
    fn malformed_codes_degrade_to_normal() {
        for code in ["", "X0000", "0", "08X00X?XXX", "570142"] {
            assert_eq!(classify_sqlstate(code), ErrorType::Normal, "{code}");
        }
    }

    #[test]
    fn classifier_only_decodes_execution_failed() {
        let classifier = SqlStateClassifier;
        // Auth/network errors keep the kernel mapping.
        assert_eq!(
            classifier.classify(&ConnectionError::NetworkFailure),
            ErrorType::ConnectionLost
        );
        assert_eq!(
            classifier.classify(&ConnectionError::AuthFailed),
            ErrorType::Normal
        );
        // SQLSTATE present and missing.
        let aborted = classifier.classify(&ConnectionError::ExecutionFailed {
            sqlstate: Some("25P02".to_owned()),
            message: "current transaction is aborted".to_owned(),
        });
        assert_eq!(aborted, ErrorType::TransactionAborted);
        let unknown = classifier.classify(&ConnectionError::ExecutionFailed {
            sqlstate: Some("42601".to_owned()),
            message: "syntax error".to_owned(),
        });
        assert_eq!(unknown, ErrorType::Normal);
        let no_code = classifier.classify(&ConnectionError::ExecutionFailed {
            sqlstate: None,
            message: "no code provided".to_owned(),
        });
        assert_eq!(no_code, ErrorType::Normal);
    }
}
