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
//! Statement surface: `"find <collection> [with <filter-text>]"` executed
//! as a `find` command: fetch-all (`limit 0`, `singleBatch: true`) for
//! the SPI surface, cursor-id batch paging (`query_page_start` /
//! `query_page_continue`, the postgres portal-paging analog, driver-level
//! on purpose) otherwise. Filter text compiles to a BSON filter document
//! client-side WITH typed parameter values — mongo has no wire binding,
//! so `?` placeholders interpolate nothing: see `filter`. Errors around
//! arity and syntax are `Protocol`, raised before any wire round-trip.
//!
//! The write half of the surface is
//! `"insert <collection> with <json-document>"`: the JSON object after
//! `with` parses into its BSON document client-side and travels as the
//! `documents` array of an `insert` command (see `document`), reporting
//! `insert <n>` with the server's count and no result columns or rows.
//! An insert binds nothing, so it takes no parameters, and it never
//! pages — cursor paging answers `Protocol` for it.
//!
//! Multi-document ACID transactions require a replica-set session and
//! are not wired: the `DataSource` transaction-control SPI methods use
//! the trait's refusing defaults.
//! The typed mapping converts every BSON value through the shared
//! `TypedValue` contract, with extended-JSON rendering for embedded
//! documents and ISO-8601 text for UTC datetimes.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;

pub mod bson;
mod document;
mod filter;
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

/// Target resolution: a full `mongodb://` connection string wins; an
/// empty target synthesizes the equivalent URI from the `host` / `port`
/// / `database` properties (the DBeaver host-port-database form).
/// URL credentials win the user slot (properties only fill a missing
/// user); `password` and `auth_source` are property-overridable
/// (the secrets pipeline writes there). TLS policy comes from
/// `ssl_mode` / `ssl_root_cert` settings.
fn resolve_target(request: &OpenRequest) -> Result<MongoTarget, ConnectionError> {
    let user = request.properties.get("user").map(String::as_str);
    let url = if request.target.is_empty() {
        host_port_target(&request.properties)?
    } else {
        request.target.clone()
    };
    let mut target = uri::parse_target(&url, user)?;
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

/// Synthesizes a `mongodb://host:port/[database]` URL for the empty
/// target case: `host` is required (the plain host-port-database form),
/// `port` defaults to 27017, `database` defaults to the URI default
/// (`admin`). The parse is delegated to `parse_target`, so validation
/// stays in exactly one place.
fn host_port_target(
    properties: &std::collections::HashMap<String, String>,
) -> Result<String, ConnectionError> {
    let missing = || {
        ConnectionError::Protocol(
            "either a mongodb:// connection string or the 'host' property is required".to_owned(),
        )
    };
    let host = properties.get("host").filter(|host| !host.is_empty());
    let Some(host) = host else {
        return Err(missing());
    };
    let port = match properties.get("port").filter(|port| !port.is_empty()) {
        Some(port) => port
            .parse::<u16>()
            .map_err(|_| ConnectionError::Protocol(format!("invalid 'port' property: '{port}'")))?,
        None => uri::DEFAULT_PORT,
    };
    let database = properties
        .get("database")
        .filter(|database| !database.is_empty());
    Ok(match database {
        Some(database) => format!("mongodb://{host}:{port}/{database}"),
        None => format!("mongodb://{host}:{port}/"),
    })
}

/// The supported statement forms: `find <collection> [with <filter-text>]`
/// and `insert <collection> with <json-document>`. The trailing text
/// keeps its original spacing — string literals inside it may contain
/// any whitespace, so parsing slices the raw SQL instead of re-joining
/// whitespace-split tokens.
#[derive(Debug, Clone, PartialEq)]
pub struct FindStatement {
    pub collection: String,
    filter: Option<filter::Filter>,
}

/// `insert <collection> with <json-document>`: the JSON object IS the
/// payload (mongo binds nothing for it), parsed into its BSON document
/// while the statement text is still client-side.
#[derive(Debug, Clone, PartialEq)]
pub struct InsertStatement {
    pub collection: String,
    document: bson::Document,
}

/// Both statement forms a mongo connection accepts. `find` pages
/// (fetch-all or a suspended cursor); `insert` never pages.
#[derive(Debug)]
pub enum Statement {
    Find(FindStatement),
    Insert(InsertStatement),
}

impl FindStatement {
    /// Compiles the `with` filter into its BSON document with the
    /// statement parameters bound. A statement without a `with` clause
    /// takes no parameters, always (mongodb Analog of postgres binding
    /// errors appearing only at `Parse`/`Bind` time).
    fn filter_document(
        &self,
        params: &[QueryParameter],
    ) -> Result<bson::Document, ConnectionError> {
        match &self.filter {
            Some(filter) => filter.document(params),
            None if params.is_empty() => Ok(bson::Document::new()),
            None => Err(ConnectionError::Protocol(
                "find statements without a 'with' filter take no parameters".to_owned(),
            )),
        }
    }
}

/// Statement-shape protocol error: nothing was sent, the statement
/// itself is not one mongo understands.
fn statement_protocol(message: String) -> ConnectionError {
    ConnectionError::Protocol(format!("unsupported statement: {message}"))
}

/// Parses `find <collection> [with <filter-text>]` and
/// `insert <collection> with <json-document>` by slicing the raw SQL:
/// the command word and collection are single tokens, everything after
/// a standalone `with` is the verbatim filter text or the verbatim
/// document text. Both forms resolve completely client-side.
fn parse_statement(sql: &str) -> Result<Statement, ConnectionError> {
    fn unsupported() -> ConnectionError {
        statement_protocol(
            "mongo statements are 'find <collection> [with <filter>]' or 'insert <collection> with <document>'"
                .to_owned(),
        )
    }
    // Leading whitespace only separates tokens; the collection and
    // clause boundaries below still need single whitespace splits.
    let sql = sql.trim_start();
    let Some((command, tail)) = sql.split_once(char::is_whitespace) else {
        return Err(unsupported());
    };
    if command != "find" && command != "insert" {
        return Err(unsupported());
    }
    let (collection, remainder) = match tail.trim_start().split_once(char::is_whitespace) {
        Some((collection, remainder)) => (collection, remainder.trim_start()),
        None => (tail.trim_start(), ""),
    };
    if collection.is_empty() {
        return Err(unsupported());
    }
    if collection.starts_with('$') {
        return Err(statement_protocol(
            "collection names may not start with '$'".to_owned(),
        ));
    }
    let mut parts = remainder.splitn(2, char::is_whitespace);
    let clause = parts.next().unwrap_or_default();
    if !remainder.is_empty() && clause != "with" {
        return Err(statement_protocol(format!(
            "unexpected tokens after the collection: '{remainder}'"
        )));
    }
    match command {
        "insert" => {
            if remainder.is_empty() {
                return Err(statement_protocol(
                    "insert statements are 'insert <collection> with <document>'".to_owned(),
                ));
            }
            let text = parts.next().unwrap_or_default().trim_start();
            let document = document::parse_document_literal(text)?;
            Ok(Statement::Insert(InsertStatement {
                collection: collection.to_owned(),
                document,
            }))
        }
        _ => {
            let filter = if remainder.is_empty() {
                None
            } else {
                // 'find c with' with nothing after dies in the empty-filter
                // protocol error of the filter parser.
                Some(filter::parse_filter(
                    parts.next().unwrap_or_default().trim_start(),
                )?)
            };
            Ok(Statement::Find(FindStatement {
                collection: collection.to_owned(),
                filter,
            }))
        }
    }
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

    /// Typed core shared by both SPI surfaces. The filter compiles and
    /// binds parameter values BEFORE any wire round-trip: arity and
    /// syntax failures are pure client-side protocol errors.
    async fn find_typed(
        &self,
        statement: &FindStatement,
        params: &[QueryParameter],
    ) -> Result<TypedStatementResult, ConnectionError> {
        let filter = statement.filter_document(params)?;
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        let documents = connection.find(&statement.collection, &filter).await?;
        let affected =
            i64::try_from(documents.len()).map_err(|_| ConnectionError::DriverFailure)?;
        Ok(bson::documents_to_result(
            &documents,
            Some(&format!("find {affected}")),
            Some(affected),
        ))
    }

    /// Typed insert core: the document was parsed and validated while
    /// the statement text was still client-side, so the only check left
    /// is arity — mongo binds nothing for a document, therefore any
    /// parameter is a protocol error raised BEFORE the connection is
    /// locked. The result reports no columns and no rows, only the
    /// server's `insert <n>` tag and count.
    async fn insert_typed(
        &self,
        statement: &InsertStatement,
        params: &[QueryParameter],
    ) -> Result<TypedStatementResult, ConnectionError> {
        if !params.is_empty() {
            return Err(ConnectionError::Protocol(
                "insert statements take no parameters".to_owned(),
            ));
        }
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        let inserted = connection
            .insert(&statement.collection, &statement.document)
            .await?;
        Ok(TypedStatementResult {
            columns: Vec::new(),
            rows: Vec::new(),
            command_tag: Some(format!("insert {inserted}")),
            affected_rows: Some(inserted),
        })
    }

    /// Typed driver surface of cursor paging (postgres `TypedPage`
    /// shape). Takes the VERBATIM statement (like the postgres
    /// `query_page_start(sql, params, limit)`): `limit = 0` degenerates
    /// to fetch-all, and each batch maps through the shared
    /// `TypedValue` contract independently — mongo is schemaless, so
    /// unlike the postgres portal the columns are re-derived per batch
    /// and may legally change between batches.
    pub async fn query_page_start(
        &self,
        sql: &str,
        params: &[QueryParameter],
        limit: i32,
    ) -> Result<WirePage, ConnectionError> {
        let statement = match parse_statement(sql)? {
            Statement::Find(statement) => statement,
            Statement::Insert(_) => {
                return Err(ConnectionError::Protocol(
                    "cursor paging requires a find statement".to_owned(),
                ));
            }
        };
        let filter = statement.filter_document(params)?;
        let mut guard = self.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(ConnectionError::DriverFailure);
        };
        let page = connection
            .find_page_start(&statement.collection, &filter, limit)
            .await?;
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

    /// Typed execution: `find <collection> [with <filter>]` with `?`
    /// parameters bound to typed BSON values client-side, or
    /// `insert <collection> with <json-document>` whose JSON document
    /// IS the payload (an insert takes no parameters).
    async fn execute_statement_typed(
        &self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<TypedStatementResult, ConnectionError> {
        match parse_statement(sql)? {
            Statement::Find(statement) => self.find_typed(&statement, params).await,
            Statement::Insert(statement) => self.insert_typed(&statement, params).await,
        }
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

    /// Unwraps the `find` arm of a parsed statement so the find tests
    /// keep asserting on `FindStatement` directly.
    fn find_statement(sql: &str) -> FindStatement {
        match parse_statement(sql).expect("parsed") {
            Statement::Find(statement) => statement,
            other => panic!("expected a find statement, got {other:?}"),
        }
    }

    /// Unwraps the `insert` arm of a parsed statement.
    fn insert_statement(sql: &str) -> InsertStatement {
        match parse_statement(sql).expect("parsed") {
            Statement::Insert(statement) => statement,
            other => panic!("expected an insert statement, got {other:?}"),
        }
    }

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
        let plain = find_statement("find orders");
        assert_eq!(plain.collection, "orders");
        assert!(plain.filter.is_none());
        let spaced = find_statement("  find  system.users  ");
        assert_eq!(spaced.collection, "system.users");
        assert!(spaced.filter.is_none());
        let filtered = find_statement("find c1 with n = 3");
        assert_eq!(filtered.collection, "c1");
        assert_eq!(
            filtered.filter_document(&[]).expect("bind"),
            vec![("n".to_owned(), bson::Bson::Int32(3))]
        );
        // The filter text keeps its whitespace: string literals win.
        let spaced = find_statement("find c1 with txt = 'two  spaces'");
        assert_eq!(
            spaced.filter_document(&[]).expect("bind"),
            vec![(
                "txt".to_owned(),
                bson::Bson::String("two  spaces".to_owned())
            )]
        );
        // Two placeholders bind to exactly the two supplied params.
        let parameterized = find_statement("find c1 with n = ? and tag = ?");
        assert!(parameterized.filter_document(&[]).is_err());
        assert_eq!(
            parameterized
                .filter_document(&[
                    QueryParameter::Integer(7),
                    QueryParameter::Text("a".to_owned()),
                ])
                .expect("bind"),
            vec![
                ("n".to_owned(), bson::Bson::Int64(7)),
                ("tag".to_owned(), bson::Bson::String("a".to_owned())),
            ]
        );
        assert!(parse_statement("").is_err());
        assert!(parse_statement("find").is_err());
        assert!(parse_statement("drop db").is_err());
        assert!(parse_statement("find db extra").is_err());
        assert!(parse_statement("find c1 with").is_err());
        assert!(parse_statement("find c1 with n = ? and").is_err());
        assert!(parse_statement("find $cmd").is_err());
    }

    #[test]
    fn insert_statements_parse_their_collection() {
        let statement = insert_statement(
            r#"insert components with {"codeGroup":"1","listComponent":[{"codeComponent":"1"}]}"#,
        );
        assert_eq!(statement.collection, "components");
        assert_eq!(
            statement.document,
            vec![
                ("codeGroup".to_owned(), bson::Bson::String("1".to_owned())),
                (
                    "listComponent".to_owned(),
                    bson::Bson::Array(vec![bson::Bson::Document(vec![(
                        "codeComponent".to_owned(),
                        bson::Bson::String("1".to_owned())
                    )])]),
                ),
            ],
            "the JSON document arrives as its BSON shape, field order intact"
        );

        let spaced = insert_statement(r#"  insert  vuce.landing  with {"a":1}  "#);
        assert_eq!(spaced.collection, "vuce.landing");
        assert_eq!(
            spaced.document,
            vec![("a".to_owned(), bson::Bson::Int32(1))]
        );

        // Structural failures stay client-side protocol errors: no
        // collection, no `with`, no document, a non-object document, a
        // malformed document, a `$` collection and stray tokens.
        assert!(parse_statement("insert").is_err());
        assert!(parse_statement("insert components").is_err());
        assert!(parse_statement("insert components with").is_err());
        assert!(parse_statement(r#"insert components with [{"a":1}]"#).is_err());
        assert!(parse_statement(r#"insert components with {not json}"#).is_err());
        assert!(parse_statement("insert $cmd with {}").is_err());
        assert!(parse_statement("insert components oops with {}").is_err());
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
    fn resolve_target_synthesizes_the_host_port_database_form() {
        // Empty target + host/port/database properties = the DBeaver
        // host-port-database form.
        let request = OpenRequest {
            container_id: "c1".into(),
            target: String::new(),
            properties: HashMap::from([
                ("host".to_owned(), "db.local".to_owned()),
                ("port".to_owned(), "27018".to_owned()),
                ("database".to_owned(), "vuce-landingz".to_owned()),
                ("user".to_owned(), "adm".to_owned()),
            ]),
        };
        let target = resolve_target(&request).expect("resolved");
        assert_eq!(target.host, "db.local");
        assert_eq!(target.port, 27018);
        assert_eq!(target.auth_db, "vuce-landingz");
        assert_eq!(target.user.as_deref(), Some("adm"));

        // Port and database default when omitted (27017 / admin).
        let request = OpenRequest {
            container_id: "c1".into(),
            target: String::new(),
            properties: HashMap::from([("host".to_owned(), "localhost".to_owned())]),
        };
        let target = resolve_target(&request).expect("resolved");
        assert_eq!(target.host, "localhost");
        assert_eq!(target.port, 27017);
        assert_eq!(target.auth_db, "admin");
        assert_eq!(target.user, None);

        // Neither a connection string nor 'host': client-side error.
        let request = OpenRequest {
            container_id: "c1".into(),
            target: String::new(),
            properties: HashMap::new(),
        };
        match resolve_target(&request) {
            Ok(_) => panic!("nothing to connect to"),
            Err(error) => assert!(
                matches!(error, ConnectionError::Protocol(ref message) if message.contains("'host' property"))
            ),
        }

        // A non-numeric port never reaches the wire.
        let request = OpenRequest {
            container_id: "c1".into(),
            target: String::new(),
            properties: HashMap::from([
                ("host".to_owned(), "localhost".to_owned()),
                ("port".to_owned(), "27abc".to_owned()),
            ]),
        };
        assert!(resolve_target(&request).is_err());

        // The full connection string keeps winning over the properties.
        let request = OpenRequest {
            container_id: "c1".into(),
            target: "mongodb://stringhost:27019/stringdb".into(),
            properties: HashMap::from([
                ("host".to_owned(), "ignored.local".to_owned()),
                ("port".to_owned(), "1".to_owned()),
            ]),
        };
        let target = resolve_target(&request).expect("resolved");
        assert_eq!(target.host, "stringhost");
        assert_eq!(target.port, 27019);
        assert_eq!(target.auth_db, "stringdb");
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
