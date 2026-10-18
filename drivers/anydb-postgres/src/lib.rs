#![forbid(unsafe_code)]
//! PostgreSQL driver: descriptor catalog + live factory. `open_data_source`
//! dials a real wire-protocol v3 connection (see `protocol`); the resolved
//! settings (secrets pipeline output) carry `user`/`password`/`database`
//! overrides over the target URL credentials.

// `pub` modules: driver tests act as a server side (they recompute md5/scram
// credentials), and advanced tooling can drive the wire layer directly.
pub mod auth;
pub mod classification;
pub mod protocol;
pub mod types;
pub mod url;

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;

use anydb_shared::ConnectionError;
use anydb_shared::driver::descriptor::DriverDescriptor;
use anydb_shared::driver::spi::{DataSource, DataSourceMetadata, Driver, OpenRequest};
use anydb_shared::driver::statement::{QueryParameter, StatementResult};

use crate::protocol::Connection as WireConnection;
use crate::url::{PostgresTarget, SslMode, parse_target};

#[derive(Debug)]
pub struct PostgresDriver {
    descriptor: DriverDescriptor,
}

impl Default for PostgresDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl PostgresDriver {
    pub fn new() -> Self {
        Self {
            descriptor: DriverDescriptor::new("postgresql", "PostgreSQL", true),
        }
    }

    /// Typed factory for callers that want the concrete wire data source.
    pub async fn open_wire_data_source(
        &self,
        request: OpenRequest,
    ) -> Result<Arc<WireDataSource>, ConnectionError> {
        let target = resolve_target(&request)?;
        let connection = WireConnection::connect(&target).await?;
        let metadata = DataSourceMetadata {
            product_name: "PostgreSQL".to_owned(),
            product_version: connection
                .server_params
                .get("server_version")
                .cloned()
                .unwrap_or_else(|| "unknown".to_owned()),
            driver_name: "anydb-postgres".to_owned(),
        };
        Ok(Arc::new(WireDataSource {
            connection: AsyncMutex::new(Some(connection)),
            metadata,
        }))
    }
}

/// Live data source over exactly one wire connection; commands serialize
/// behind a tokio mutex (`None` after close).
pub struct WireDataSource {
    connection: AsyncMutex<Option<WireConnection>>,
    metadata: DataSourceMetadata,
}

impl WireDataSource {
    /// Simple query over the live connection (text-format rows).
    pub async fn simple_query(&self, sql: &str) -> Result<protocol::QueryResult, ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        connection.simple_query(sql).await
    }

    /// Typed statement execution over the live connection: binary format
    /// for cataloged column types, text for the rest. Row values come back
    /// as shared `TypedValue`s (NULL is `None`).
    pub async fn execute_typed_statement(
        &self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<protocol::TypedResult, ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        connection.typed_query(sql, params).await
    }

    /// Explicit `BEGIN` over the live connection.
    pub async fn begin_transaction(&self) -> Result<(), ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        connection.begin().await
    }

    /// Explicit `COMMIT` over the live connection.
    pub async fn commit_transaction(&self) -> Result<(), ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        connection.commit().await
    }

    /// `ROLLBACK` over the live connection (also normalizes the failed
    /// transaction state back to idle).
    pub async fn rollback_transaction(&self) -> Result<(), ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        connection.rollback().await
    }
}

/// Maps a wire-layer extended result onto the shared statement contract.
fn statement_result(
    result: crate::protocol::ExtendedResult,
) -> anydb_shared::driver::statement::StatementResult {
    anydb_shared::driver::statement::StatementResult {
        columns: result.columns,
        rows: result.rows,
        command_tag: result.command_tag,
        affected_rows: result.affected_rows,
    }
}

/// URL-embedded credentials are overridden by resolved properties (the
/// secrets pipeline writes there). TLS policy comes from `ssl_mode` /
/// `ssl_root_cert` settings.
fn resolve_target(request: &OpenRequest) -> Result<PostgresTarget, ConnectionError> {
    let user = request.properties.get("user").map(String::as_str);
    let mut target = parse_target(&request.target, user)?;
    if let Some(value) = request.properties.get("password") {
        target.password = Some(value.clone());
    }
    if let Some(value) = request.properties.get("database") {
        target.database = Some(value.clone());
    }
    if let Some(value) = request.properties.get("ssl_mode") {
        target.ssl_mode = SslMode::parse(value).ok_or_else(|| {
            ConnectionError::Protocol(format!(
                "invalid ssl_mode '{value}' (expected disable|prefer|require)"
            ))
        })?;
    }
    if let Some(value) = request.properties.get("ssl_root_cert") {
        target.ssl_root_cert = Some(value.clone());
    }
    Ok(target)
}

#[async_trait]
impl Driver for PostgresDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    /// SQLSTATE-driven classification feeding the recovery loop.
    fn error_classifier(
        &self,
    ) -> Option<Arc<dyn anydb_shared::driver::classification::ErrorClassifier>> {
        Some(Arc::new(classification::SqlStateClassifier))
    }

    async fn open_data_source(
        &self,
        request: OpenRequest,
    ) -> Result<Arc<dyn DataSource>, ConnectionError> {
        Ok(self.open_wire_data_source(request).await?)
    }
}

#[async_trait]
impl DataSource for WireDataSource {
    fn metadata(&self) -> DataSourceMetadata {
        self.metadata.clone()
    }

    /// Ping via the empty simple query (server answers `EmptyQueryResponse`
    /// then `ReadyForQuery`).
    async fn ping(&self) -> Result<(), ConnectionError> {
        self.simple_query("").await.map(|_| ())
    }

    /// Extended protocol execution: unnamed statement + portal with
    /// binary-format parameters, text-format results.
    async fn execute_statement(
        &self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<StatementResult, ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        connection
            .extended_query(sql, params)
            .await
            .map(statement_result)
    }

    /// `ROLLBACK` over the live connection: normalizes the aborted
    /// transaction state back to idle.
    async fn rollback_transaction(&self) -> Result<(), ConnectionError> {
        WireDataSource::rollback_transaction(self).await
    }

    async fn close(&self) {
        if let Some(connection) = self.connection.lock().await.take() {
            connection.terminate().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_requires_resolved_target() {
        let driver = PostgresDriver::new();
        let request = OpenRequest {
            container_id: "c1".into(),
            target: String::new(),
            properties: Default::default(),
        };
        assert!(driver.open_data_source(request).await.is_err());
    }

    #[tokio::test]
    async fn open_requires_a_user() {
        let driver = PostgresDriver::new();
        let request = OpenRequest {
            container_id: "c1".into(),
            target: "postgres://127.0.0.1:1/db".into(),
            properties: Default::default(),
        };
        match driver.open_data_source(request).await {
            Ok(_) => panic!("must fail without a user"),
            Err(error) => assert_eq!(
                error,
                ConnectionError::Protocol("missing user in target URL or properties".to_owned())
            ),
        }
    }
}
