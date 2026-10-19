#![forbid(unsafe_code)]
//! MongoDB driver over the OP_MSG wire protocol (this vertical replaces
//! the query-only skeleton): `hello` handshake with
//! `saslSupportedMechs` negotiation, SCRAM-SHA-1/256 authentication and
//! typed mapping through the `bson` module (the DBeaver
//! `DocumentValueExtractor` analog). Declared thread-safe is `false` on
//! purpose so the serialized statement gate path (`SingleThreadLock`
//! analog) is exercised from day one.
//!
//! Transport: plain TCP or rustls TLS from the first byte
//! (`ssl_mode: disable|require`, certificates always verified — there
//! is no `prefer` because mongo has no negotiation probe).
//!
//! Statement surface: `"find <collection>"` executed as a single-batch
//! `find` command (`singleBatch: true`, cursor closed). Parameters are
//! not supported yet (a filter document language is future work); the
//! typed mapping converts every BSON value through the shared
//! `TypedValue` contract, with extended-JSON rendering for embedded
//! documents and ISO-8601 text for UTC datetimes. Cursor-id batch
//! paging (`query_page_start` / `query_page_continue`, the postgres
//! portal-paging analog) is driver-level on purpose.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;

pub mod bson;
mod op_msg;
mod scram;
pub mod uri;
pub mod wire;

use anydb_shared::ConnectionError;
use anydb_shared::driver::descriptor::DriverDescriptor;
use anydb_shared::driver::spi::{DataSource, DataSourceMetadata, Driver, OpenRequest};
use anydb_shared::driver::statement::{QueryParameter, StatementResult, TypedStatementResult};

use crate::uri::{MongoTarget, SslMode};
use crate::wire::Connection as WireConnection;

/// One typed batch of the driver-level paging surface: the mongo
/// rendering of the postgres `TypedPage` contract (`result` plus
/// `suspended`).
pub type WirePage = wire::TypedPage;

/// Maps a raw wire batch through the shared typed contract.
fn typed_batch(page: &wire::CursorPage) -> WirePage {
    wire::typed_page(page)
}

#[derive(Debug)]
pub struct MongoDriver {
    descriptor: DriverDescriptor,
}

impl Default for MongoDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl MongoDriver {
    pub fn new() -> Self {
        Self {
            descriptor: DriverDescriptor::new("mongodb", "MongoDB", false),
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
            product_name: "MongoDB".to_owned(),
            product_version: connection.server_version().to_owned(),
            driver_name: "anydb-mongo".to_owned(),
        };
        Ok(Arc::new(WireDataSource {
            connection: AsyncMutex::new(Some(connection)),
            metadata,
        }))
    }
}

/// URL credentials win the user slot (properties only fill a missing
/// user); `password` and `auth_source` are property-overridable
/// (the secrets pipeline writes there). TLS policy comes from
/// `ssl_mode` / `ssl_root_cert` settings.
fn resolve_target(request: &OpenRequest) -> Result<MongoTarget, ConnectionError> {
    let user = request.properties.get("user").map(String::as_str);
    let mut target = uri::parse_target(&request.target, user)?;
    if let Some(value) = request.properties.get("password") {
        target.password = Some(value.clone());
    }
    if let Some(value) = request.properties.get("auth_source")
        && !value.is_empty()
    {
        target.auth_db = value.clone();
    }
    if let Some(value) = request.properties.get("ssl_mode") {
        target.ssl_mode = SslMode::parse(value).ok_or_else(|| {
            ConnectionError::Protocol(format!(
                "invalid ssl_mode '{value}' (expected disable|require)"
            ))
        })?;
    }
    if let Some(value) = request.properties.get("ssl_root_cert") {
        target.ssl_root_cert = Some(value.clone());
    }
    Ok(target)
}

/// The only statement form this vertical supports: `find <collection>`
/// (single token, no whitespace).
fn parse_find_statement(sql: &str) -> Result<String, ConnectionError> {
    fn protocol(message: String) -> ConnectionError {
        ConnectionError::Protocol(format!("unsupported statement: {message}"))
    }
    let mut tokens = sql.split_whitespace();
    let (Some(command), Some(collection)) = (tokens.next(), tokens.next()) else {
        return Err(protocol(
            "mongo statements are 'find <collection>'".to_owned(),
        ));
    };
    if command != "find" {
        return Err(protocol(
            "mongo statements are 'find <collection>'".to_owned(),
        ));
    }
    if tokens.next().is_some() {
        return Err(protocol(
            "mongo statements are 'find <collection>' (one trailing token)".to_owned(),
        ));
    }
    if collection.starts_with('$') {
        return Err(protocol(
            "collection names may not start with '$'".to_owned(),
        ));
    }
    Ok(collection.to_owned())
}

/// Live data source over exactly one wire connection; commands serialize
/// behind a tokio mutex (`None` after close).
#[derive(Debug)]
pub struct WireDataSource {
    connection: AsyncMutex<Option<WireConnection>>,
    metadata: DataSourceMetadata,
}

impl WireDataSource {
    /// Driver-level factory for direct wire tests (no lifecycle
    /// pipeline involved).
    pub async fn open(target: &MongoTarget) -> Result<Arc<Self>, ConnectionError> {
        let connection = WireConnection::connect(target).await?;
        let metadata = DataSourceMetadata {
            product_name: "MongoDB".to_owned(),
            product_version: connection.server_version().to_owned(),
            driver_name: "anydb-mongo".to_owned(),
        };
        Ok(Arc::new(Self {
            connection: AsyncMutex::new(Some(connection)),
            metadata,
        }))
    }

    /// Typed core shared by both SPI surfaces.
    async fn find_typed(
        &self,
        collection: String,
    ) -> Result<TypedStatementResult, ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        let documents = connection.find(&collection).await?;
        let affected =
            i64::try_from(documents.len()).map_err(|_| ConnectionError::DriverFailure)?;
        Ok(bson::documents_to_result(
            &documents,
            Some(&format!("find {affected}")),
            Some(affected),
        ))
    }

    /// Typed driver surface of cursor paging (postgres `TypedPage`
    /// shape). `limit = 0` degenerates to fetch-all. Each batch maps
    /// through the shared `TypedValue` contract independently: mongo is
    /// schemaless, so unlike the postgres portal the columns are
    /// re-derived per batch and may legally change between batches.
    pub async fn query_page_start(
        &self,
        collection: &str,
        limit: i32,
    ) -> Result<WirePage, ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        let page = connection.find_page_start(collection, limit).await?;
        Ok(typed_batch(&page))
    }

    /// Continues the suspended cursor for the next batch; see
    /// `query_page_start`.
    pub async fn query_page_continue(&self) -> Result<WirePage, ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        let page = connection.find_page_continue().await?;
        Ok(typed_batch(&page))
    }
}

#[async_trait]
impl DataSource for WireDataSource {
    fn metadata(&self) -> DataSourceMetadata {
        self.metadata.clone()
    }

    /// Keepalive ping command (`{ping: 1}`).
    async fn ping(&self) -> Result<(), ConnectionError> {
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        connection.ping().await
    }

    /// Text surface over the typed core: every value renders through
    /// the platform-friendly `TypedValue` display.
    async fn execute_statement(
        &self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<StatementResult, ConnectionError> {
        let typed = DataSource::execute_statement_typed(self, sql, params).await?;
        Ok(StatementResult {
            columns: typed.columns,
            rows: typed
                .rows
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(|cell| cell.map(|value| value.to_string()))
                        .collect()
                })
                .collect(),
            command_tag: typed.command_tag,
            affected_rows: typed.affected_rows,
        })
    }

    /// Typed execution: the shared `TypedValue` contract applied to
    /// every BSON value (embedded documents as extended JSON, datetimes
    /// as ISO-8601 text).
    async fn execute_statement_typed(
        &self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<TypedStatementResult, ConnectionError> {
        if !params.is_empty() {
            return Err(ConnectionError::Protocol(
                "'find <collection>' statements take no parameters yet".to_owned(),
            ));
        }
        let collection = parse_find_statement(sql)?;
        self.find_typed(collection).await
    }

    async fn close(&self) {
        if let Some(connection) = self.connection.lock().await.take() {
            connection.terminate().await;
        }
    }
}

#[async_trait]
impl Driver for MongoDriver {
    fn descriptor(&self) -> &DriverDescriptor {
        &self.descriptor
    }

    async fn open_data_source(
        &self,
        request: OpenRequest,
    ) -> Result<Arc<dyn DataSource>, ConnectionError> {
        Ok(self.open_wire_data_source(request).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    #[test]
    fn driver_is_declared_not_thread_safe() {
        let driver = MongoDriver::new();
        assert!(!driver.descriptor().thread_safe);
    }

    #[tokio::test]
    async fn open_requires_resolved_target() {
        let driver = MongoDriver::new();
        let request = OpenRequest {
            container_id: "c1".into(),
            target: String::new(),
            properties: Default::default(),
        };
        assert!(driver.open_data_source(request).await.is_err());
    }

    #[tokio::test]
    async fn open_requires_host_after_scheme() {
        let driver = MongoDriver::new();
        let request = OpenRequest {
            container_id: "c1".into(),
            target: "mongodb:///shop".into(),
            properties: Default::default(),
        };
        match driver.open_data_source(request).await {
            Ok(_) => panic!("missing host must fail"),
            Err(error) => assert!(matches!(error, ConnectionError::Protocol(_))),
        }
    }

    #[test]
    fn find_statements_parse_their_collection() {
        assert_eq!(
            parse_find_statement("find orders").expect("parsed"),
            "orders"
        );
        assert_eq!(
            parse_find_statement("  find  system.users  ").expect("parsed"),
            "system.users"
        );
        assert!(parse_find_statement("").is_err());
        assert!(parse_find_statement("find").is_err());
        assert!(parse_find_statement("drop db").is_err());
        assert!(parse_find_statement("find db extra").is_err());
        assert!(parse_find_statement("find $cmd").is_err());
    }

    #[test]
    fn resolve_target_prefers_properties_over_url_credentials() {
        let request = OpenRequest {
            container_id: "c1".into(),
            target: "mongodb://urluser:urlpass@host:1/urlauth".into(),
            properties: HashMap::from([
                ("user".to_owned(), "puser".to_owned()),
                ("password".to_owned(), "ppass".to_owned()),
                ("auth_source".to_owned(), "pauth".to_owned()),
            ]),
        };
        let target = resolve_target(&request).expect("resolved");
        assert_eq!(target.user.as_deref(), Some("urluser"));
        assert_eq!(target.password.as_deref(), Some("ppass"));
        assert_eq!(target.auth_db, "pauth");
    }

    #[test]
    fn resolve_target_applies_tls_settings() {
        let request = OpenRequest {
            container_id: "c1".into(),
            target: "mongodb://host:1".into(),
            properties: HashMap::from([
                ("ssl_mode".to_owned(), "require".to_owned()),
                ("ssl_root_cert".to_owned(), "C:/roots/host.pem".to_owned()),
            ]),
        };
        let target = resolve_target(&request).expect("resolved");
        assert_eq!(target.ssl_mode, SslMode::Require);
        assert_eq!(target.ssl_root_cert.as_deref(), Some("C:/roots/host.pem"));

        let request = OpenRequest {
            container_id: "c1".into(),
            target: "mongodb://host:1".into(),
            properties: HashMap::from([("ssl_mode".to_owned(), "prefer".to_owned())]),
        };
        match resolve_target(&request) {
            Ok(_) => panic!("'prefer' is not a mongo mode"),
            Err(error) => assert!(
                matches!(error, ConnectionError::Protocol(ref message) if message.contains("invalid ssl_mode")),
                "unexpected error: {error:?}"
            ),
        }
    }

    #[test]
    fn resolve_target_falls_back_to_url_credentials() {
        let request = OpenRequest {
            container_id: "c1".into(),
            target: "mongodb://urluser@host:1".into(),
            properties: HashMap::new(),
        };
        let target = resolve_target(&request).expect("resolved");
        assert_eq!(target.user.as_deref(), Some("urluser"));
        assert_eq!(target.password, None);
        assert_eq!(target.auth_db, "admin");
    }
}
