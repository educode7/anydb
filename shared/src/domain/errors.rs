//! Connection error taxonomy plus the recovery classification rules
//! (DBeaver `DBPErrorAssistant` / `RecoveryState` analog).

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    #[error("the data source container was not registered")]
    ContainerNotFound,
    #[error("data source is already connected")]
    AlreadyConnected,
    #[error("a connect is already in progress")]
    ConnectingInProgress,
    #[error("a disconnect is already in progress")]
    DisconnectingInProgress,
    #[error("data source is disconnected")]
    AlreadyDisconnected,
    #[error("data source is still connected")]
    StillConnected,
    #[error("authentication failed")]
    AuthFailed,
    #[error("connection secrets are unavailable")]
    MissingSecrets,
    #[error("network handler failure")]
    NetworkFailure,
    #[error("protocol failure: {0}")]
    /// Driver wire/protocol-level failure. Message detail is produced by
    /// drivers and must never embed secrets (user/password).
    Protocol(String),
    #[error("statement execution failed: {0}")]
    /// Server-reported statement execution error (SQL runtime failures).
    /// Detail comes from the server error response and must not embed
    /// secrets (user/password).
    ExecutionFailed(String),
    #[error("driver failure")]
    DriverFailure,
    #[error("operation canceled")]
    Canceled,
}

pub type ConnectionResult<T> = Result<T, ConnectionError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorType {
    Normal,
    ExecutionCanceled,
    TransactionAborted,
    ConnectionLost,
}

impl ErrorType {
    /// Conservative classification for drivers that do not ship their own
    /// `ErrorClassifier` (DBeaver drivers override `discoverErrorType`).
    pub fn default_classify(error: &ConnectionError) -> Self {
        match error {
            ConnectionError::Canceled => ErrorType::ExecutionCanceled,
            ConnectionError::NetworkFailure => ErrorType::ConnectionLost,
            _ => ErrorType::Normal,
        }
    }

    /// Only recoverable classes get an invalidation scope (evidence digest 4.1:
    /// `TRANSACTION_ABORTED` / `CONNECTION_LOST` are the sole recoverable types).
    pub fn recovery_scope(self) -> Option<RecoveryScope> {
        match self {
            ErrorType::TransactionAborted => Some(RecoveryScope::Transactions),
            ErrorType::ConnectionLost => Some(RecoveryScope::DataSource),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryScope {
    Transactions,
    DataSource,
}
