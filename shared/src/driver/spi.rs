//! Factory seam and data source contract (DBeaver
//! `DBPDataSourceProvider.openDataSource` analog).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use super::classification::ErrorClassifier;
use super::descriptor::DriverDescriptor;
use super::statement::{QueryParameter, StatementResult, TypedStatementResult};
use crate::ConnectionError;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    pub container_id: String,
    /// Resolved target (URL or logical name) after the connect pipeline stages.
    pub target: String,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSourceMetadata {
    pub product_name: String,
    pub product_version: String,
    pub driver_name: String,
}

#[async_trait]
pub trait Driver: Send + Sync {
    fn descriptor(&self) -> &DriverDescriptor;

    /// DBeaver per-driver `discoverErrorType` override analog: classifiers
    /// that decode driver-native error payloads (PostgreSQL: SQLSTATE).
    /// `None` selects the kernel's conservative classification.
    fn error_classifier(&self) -> Option<Arc<dyn ErrorClassifier>> {
        None
    }

    /// Factory seam decoupling connection creation from the registry.
    async fn open_data_source(
        &self,
        request: OpenRequest,
    ) -> Result<Arc<dyn DataSource>, ConnectionError>;
}

#[async_trait]
pub trait DataSource: Send + Sync {
    fn metadata(&self) -> DataSourceMetadata;

    /// Keepalive probe for the `KeepAlivePingJob` analog.
    async fn ping(&self) -> Result<(), ConnectionError>;

    /// Executes one statement with parameters over the driver's prepared /
    /// extended path (text-format results, `QueryParameter` typed input).
    /// Default implementation: the driver does not support statement
    /// execution (query-only readers), surfacing
    /// `ConnectionError::DriverFailure`.
    async fn execute_statement(
        &self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<StatementResult, ConnectionError> {
        let _ = (sql, params);
        Err(ConnectionError::DriverFailure)
    }

    /// Typed execution: the same statement contract with the driver's own
    /// binary / text type catalog applied (DBeaver `TypedValue` analog).
    /// Default: not supported (query-only readers), surfacing
    /// `ConnectionError::DriverFailure`.
    async fn execute_statement_typed(
        &self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<TypedStatementResult, ConnectionError> {
        let _ = (sql, params);
        Err(ConnectionError::DriverFailure)
    }

    /// Runs one statement through the driver's SQL-keyed prepared
    /// statement cache when supported (DBeaver `DBCStatement` cache
    /// analog). Default: plain uncached typed execution, so the contract
    /// degrades gracefully for drivers without session caching.
    async fn execute_cached_statement_typed(
        &self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<TypedStatementResult, ConnectionError> {
        self.execute_statement_typed(sql, params).await
    }

    /// Rolls back the live transaction after an abort (DBeaver invalidates
    /// transactions by running a rollback). Default: the driver does not
    /// carry transaction semantics, surfacing
    /// `ConnectionError::DriverFailure`.
    async fn rollback_transaction(&self) -> Result<(), ConnectionError> {
        Err(ConnectionError::DriverFailure)
    }

    async fn close(&self);
}
