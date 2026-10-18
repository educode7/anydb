//! PostgreSQL frontend protocol v3: startup, authentication exchange
//! (trust / cleartext / md5 / SCRAM-SHA-256), TLS upgrade (SSLRequest then
//! rustls handshake) and the simple query protocol.
//!
//! `pub` for driver tests and advanced tooling; typical users go through
//! `PostgresDriver`.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

use anydb_shared::ConnectionError;
use anydb_shared::driver::statement::QueryParameter;
use anydb_shared::driver::statement::TypedValue;

/// Bind request section shared by both extended flows: parameter format
/// list (every parameter binary), values with their lengths (`-1` never
/// sends value bytes), minus portal/statement names and result formats.
fn bind_param_section(params: &[QueryParameter]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(params.len() as i16).to_be_bytes());
    for _ in params {
        payload.extend_from_slice(&1i16.to_be_bytes());
    }
    payload.extend_from_slice(&(params.len() as i16).to_be_bytes());
    for param in params {
        match param_binary(param) {
            Some(bytes) => {
                payload.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                payload.extend(bytes);
            }
            None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    payload
}

/// `Parse` payload for one prepared statement (named or unnamed): sql plus
/// declared parameter type OIDs.
fn parse_message_payload(name: &str, sql: &str, params: &[QueryParameter]) -> Vec<u8> {
    let mut parse_payload = name.as_bytes().to_vec();
    parse_payload.push(0);
    parse_payload.extend_from_slice(sql.as_bytes());
    parse_payload.push(0);
    parse_payload.extend_from_slice(&(params.len() as i16).to_be_bytes());
    for param in params {
        parse_payload.extend_from_slice(&param_type_oid(param).to_be_bytes());
    }
    parse_payload
}

/// `Bind` payload: portal and statement names, binary-format parameter
/// values and the requested result formats (one per column; `0` applies to
/// all when the list is a single text entry or the statement has no
/// columns).
fn bind_message_payload(
    portal: &str,
    statement: &str,
    params: &[QueryParameter],
    result_formats: &[i16],
) -> Vec<u8> {
    let mut payload = portal.as_bytes().to_vec();
    payload.push(0);
    payload.extend_from_slice(statement.as_bytes());
    payload.push(0);
    payload.extend(bind_param_section(params));
    payload.extend_from_slice(&(result_formats.len() as i16).to_be_bytes());
    for format in result_formats {
        payload.extend_from_slice(&(*format).to_be_bytes());
    }
    payload
}

use crate::auth::{self, ScramClient};
use crate::types;
use crate::url::{PostgresTarget, SslMode};

/// Postgres type OIDs for the SPI parameter set (binary-format encoding).
const OID_BOOL: i32 = 16;
const OID_INT8: i32 = 20;
const OID_BYTEA: i32 = 17;
const OID_TEXT: i32 = 25;
const OID_FLOAT8: i32 = 701;

/// Declared type OID for one SPI parameter (`0` = unknown: only NULL uses
/// this, letting the server infer the type from the statement context).
fn param_type_oid(param: &QueryParameter) -> i32 {
    match param {
        QueryParameter::Null => 0,
        QueryParameter::Boolean(_) => OID_BOOL,
        QueryParameter::Integer(_) => OID_INT8,
        QueryParameter::Float(_) => OID_FLOAT8,
        QueryParameter::Text(_) => OID_TEXT,
        QueryParameter::Binary(_) => OID_BYTEA,
    }
}

/// Binary-format (1) value bytes; `None` for NULL (negative length on the
/// wire). `Text` and `Binary` share the same length-prefixed layout, so the
/// byte form is identical for both formats.
fn param_binary(param: &QueryParameter) -> Option<Vec<u8>> {
    match param {
        QueryParameter::Null => None,
        QueryParameter::Boolean(value) => Some(vec![u8::from(*value)]),
        QueryParameter::Integer(value) => Some(value.to_be_bytes().to_vec()),
        QueryParameter::Float(value) => Some(value.to_be_bytes().to_vec()),
        QueryParameter::Text(value) => Some(value.clone().into_bytes()),
        QueryParameter::Binary(value) => Some(value.clone()),
    }
}

/// One extended-query execution outcome: text-format rows plus the command
/// tag metadata (shared `StatementResult` fields, extended-protocol shaped).
#[derive(Debug, Clone, PartialEq)]
pub struct ExtendedResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    pub command_tag: Option<String>,
    pub affected_rows: Option<i64>,
}

/// One described column of a typed execution.
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnMeta {
    pub name: String,
    pub oid: i32,
}

/// One typed-query execution outcome: described columns with their OIDs,
/// typed values per row (NULL is `None`), and the command tag metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedResult {
    pub columns: Vec<ColumnMeta>,
    pub rows: Vec<Vec<Option<TypedValue>>>,
    pub command_tag: Option<String>,
    pub affected_rows: Option<i64>,
}

/// A named prepared statement on the server (DBeaver prepared-statement
/// reuse analog): reusable across transactions until the session ends or
/// the name is re-`Parse`d. Valid only on connections that share the
/// session where it was prepared.
#[derive(Debug, Clone, PartialEq)]
pub struct Prepared {
    pub name: String,
    pub sql: String,
    /// Server-declared parameter type OIDs (server inference applied).
    pub param_oids: Vec<i32>,
    /// Result columns as described at prepare time.
    pub columns: Vec<ColumnMeta>,
    /// Catalog-chosen binary/text result formats (stable per statement).
    pub result_formats: Vec<i16>,
}

/// Protocol 3.0 major=3 minor=0 → 196608 (standard startup since PostgreSQL 7.4).
pub const PROTOCOL_VERSION_3: i32 = 196608;

/// SSLRequest magic code (PostgreSQL docs, "SSL Protocol Version Number").
pub const SSL_REQUEST_CODE: i32 = 80877103;

/// One simple-query result: column names plus text-format values.
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
}

/// Transport-agnostic stream: plaintext TCP or a completed TLS 1.x session.
pub enum NetStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for NetStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for NetStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

/// Transaction status reported by `ReadyForQuery` (`I` idle, `T` inside a
/// transaction, `E` failed transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TxnStatus {
    #[default]
    Idle,
    InTransaction,
    Failed,
}

fn status_from_byte(byte: u8) -> Result<TxnStatus, ConnectionError> {
    match byte {
        b'I' => Ok(TxnStatus::Idle),
        b'T' => Ok(TxnStatus::InTransaction),
        b'E' => Ok(TxnStatus::Failed),
        other => Err(ConnectionError::Protocol(format!(
            "unknown transaction status {other}"
        ))),
    }
}

/// A live frontend connection. Single-owner by design; the data source
/// wrapper serializes access behind a tokio mutex.
pub struct Connection {
    stream: NetStream,
    /// `ParameterStatus` values seen during startup (`server_version`, ...).
    pub server_params: HashMap<String, String>,
    /// Last `ReadyForQuery` transaction status (`I`/`T`/`E`).
    txn_status: TxnStatus,
    /// SQL-keyed prepared statement cache (per session, dies with the
    /// connection).
    statements: StatementCache,
    /// Serial source for internal prepared statement names (`dbpN`), kept
    /// separate from user-provided names.
    next_statement_id: u64,
}

/// Bound of the SQL-keyed statement cache. DBeaver ships the same default
/// (`maxStatements` = 200).
const STATEMENT_CACHE_MAX: usize = 200;

/// SQL-keyed prepared statement cache (DBeaver `DBCStatement` cache
/// analog): bounded LRU. Named handles are session-scoped, so the cache
/// dies with the connection; re-connection starts empty. Evicted handles
/// leak server-side until the session ends (the server keeps preparing
/// more than 200 statements only if its own catalog bound allows).
#[derive(Debug)]
struct StatementCache {
    max: usize,
    /// Least-recently-used first.
    order: VecDeque<String>,
    entries: HashMap<String, Prepared>,
}

impl StatementCache {
    fn new(max: usize) -> Self {
        Self {
            max,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    /// Returns the prepared entry for `sql`, bumping it to most recently
    /// used.
    fn get(&mut self, sql: &str) -> Option<Prepared> {
        let prepared = self.entries.get(sql)?.clone();
        if let Some(position) = self.order.iter().position(|entry| entry == sql) {
            self.order.remove(position);
        }
        self.order.push_back(sql.to_owned());
        Some(prepared)
    }

    /// Inserts the prepared entry for its own SQL, evicting the least
    /// recently used when bound is reached.
    fn put(&mut self, prepared: Prepared) {
        if self.entries.contains_key(&prepared.sql)
            && let Some(position) = self.order.iter().position(|entry| entry == &prepared.sql)
        {
            self.order.remove(position);
        }
        while self.entries.len() >= self.max {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.order.push_back(prepared.sql.clone());
        self.entries.insert(prepared.sql.clone(), prepared);
    }
}

fn io_err() -> ConnectionError {
    ConnectionError::NetworkFailure
}

fn slice4(payload: &[u8]) -> Result<[u8; 4], ConnectionError> {
    payload
        .try_into()
        .map_err(|_| ConnectionError::Protocol("truncated 32-bit field".to_owned()))
}

fn slice2(payload: &[u8]) -> Result<[u8; 2], ConnectionError> {
    payload
        .try_into()
        .map_err(|_| ConnectionError::Protocol("truncated 16-bit field".to_owned()))
}

async fn read_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> Result<(), ConnectionError> {
    stream
        .read_exact(buf)
        .await
        .map(|_| ())
        .map_err(|_| io_err())
}

/// Reads one backend message; the length prefix (which counts itself) is
/// consumed and validated.
async fn read_message<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u8, Vec<u8>), ConnectionError> {
    let mut tag = [0u8; 1];
    read_exact(stream, &mut tag).await?;
    let mut length = [0u8; 4];
    read_exact(stream, &mut length).await?;
    let len = i32::from_be_bytes(length);
    if len < 4 {
        return Err(ConnectionError::Protocol(format!(
            "invalid message length {len}"
        )));
    }
    let mut payload = vec![0u8; (len - 4) as usize];
    read_exact(stream, &mut payload).await?;
    Ok((tag[0], payload))
}

async fn write_all<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
) -> Result<(), ConnectionError> {
    stream.write_all(bytes).await.map_err(|_| io_err())?;
    stream.flush().await.map_err(|_| io_err())
}

/// Writes one frontend message: `[tag][len][payload]`, len includes itself.
async fn write_message<S: AsyncWrite + Unpin>(
    stream: &mut S,
    tag: u8,
    payload: &[u8],
) -> Result<(), ConnectionError> {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(tag);
    frame.extend_from_slice(&(payload.len() as i32 + 4).to_be_bytes());
    frame.extend_from_slice(payload);
    write_all(stream, &frame).await
}

/// Writes the startup packet (no tag byte: the only frontend message without
/// one besides SSLRequest).
async fn write_startup<S: AsyncWrite + Unpin>(
    stream: &mut S,
    params: &[(&str, Option<&str>)],
) -> Result<(), ConnectionError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&PROTOCOL_VERSION_3.to_be_bytes());
    for (key, value) in params {
        let Some(value) = value else { continue };
        payload.extend_from_slice(key.as_bytes());
        payload.push(0);
        payload.extend_from_slice(value.as_bytes());
        payload.push(0);
    }
    payload.push(0);
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as i32 + 4).to_be_bytes());
    frame.extend_from_slice(&payload);
    write_all(stream, &frame).await
}

/// SSLRequest: `[len=8][code]`, no tag byte; the server answers either
/// 'S' (proceed with TLS) or 'N' (plaintext only).
async fn write_ssl_request(stream: &mut TcpStream) -> Result<(), ConnectionError> {
    let mut frame = [0u8; 8];
    frame[0..4].copy_from_slice(&8i32.to_be_bytes());
    frame[4..8].copy_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
    write_all(stream, &frame).await
}

/// Builds the rustls client config: OS roots by default, PEM file override
/// with `ssl_root_cert`. Certificate verification is always on.
fn tls_client_config(target: &PostgresTarget) -> Result<Arc<ClientConfig>, ConnectionError> {
    let mut roots = RootCertStore::empty();
    match &target.ssl_root_cert {
        Some(path) => {
            let pem_iter = CertificateDer::pem_file_iter(path).map_err(|_| {
                ConnectionError::Protocol(format!("cannot read ssl_root_cert file: {path}"))
            })?;
            let mut loaded = 0usize;
            for cert in pem_iter {
                let cert = cert.map_err(|_| {
                    ConnectionError::Protocol(format!("invalid PEM certificate in {path}"))
                })?;
                roots.add_parsable_certificates([cert]);
                loaded += 1;
            }
            if loaded == 0 || roots.is_empty() {
                return Err(ConnectionError::Protocol(format!(
                    "no usable root certificates in {path}"
                )));
            }
        }
        None => {
            // OS trust store; `CertificateResult` reports load errors inline.
            let native = rustls_native_certs::load_native_certs();
            if !native.errors.is_empty() {
                return Err(ConnectionError::Protocol(format!(
                    "cannot load native root certificates: {}",
                    native.errors[0]
                )));
            }
            if native.certs.is_empty() {
                return Err(ConnectionError::Protocol(
                    "no trusted root certificates available in the OS store".to_owned(),
                ));
            }
            roots.add_parsable_certificates(native.certs);
        }
    }

    let builder =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|_| {
                ConnectionError::Protocol("TLS protocol versions unavailable".to_owned())
            })?;
    let config = builder.with_root_certificates(roots).with_no_client_auth();
    Ok(Arc::new(config))
}

/// SSLRequest + TLS handshake. Always full certificate verification.
async fn tls_upgrade(
    stream: TcpStream,
    target: &PostgresTarget,
) -> Result<NetStream, ConnectionError> {
    let connector = TlsConnector::from(tls_client_config(target)?);
    let server_name = ServerName::try_from(target.host.clone()).map_err(|_| {
        ConnectionError::Protocol(format!("invalid TLS server name: {}", target.host))
    })?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| ConnectionError::Protocol(format!("TLS handshake failed: {error}")))?;
    Ok(NetStream::Tls(Box::new(tls_stream)))
}

/// Parses an `ErrorResponse`/`NoticeResponse` payload: repeated
/// `(u8 field-code, cstring value)` pairs, zero-terminated list.
fn parse_fields(payload: &[u8]) -> HashMap<char, String> {
    let mut fields = HashMap::new();
    let mut i = 0;
    while i < payload.len() && payload[i] != 0 {
        let code = payload[i] as char;
        i += 1;
        let start = i;
        while i < payload.len() && payload[i] != 0 {
            i += 1;
        }
        fields.insert(
            code,
            String::from_utf8_lossy(&payload[start..i]).into_owned(),
        );
        i += 1;
    }
    fields
}

fn error_response(payload: &[u8]) -> ConnectionError {
    let fields = parse_fields(payload);
    let message = fields
        .get(&'M')
        .map(String::as_str)
        .unwrap_or("unknown server error");
    match fields.get(&'S').map(String::as_str) {
        Some("FATAL") | Some("ERROR") => ConnectionError::AuthFailed,
        _ => ConnectionError::Protocol(format!("server error: {message}")),
    }
}

/// Runtime (post-startup) errors are statement execution failures, not
/// authentication problems: everything lands in `ExecutionFailed` with the
/// SQLSTATE (`C` field) attached for per-driver classification.
fn runtime_error_response(payload: &[u8]) -> ConnectionError {
    let fields = parse_fields(payload);
    let sqlstate = fields.get(&'C').cloned();
    let message = fields
        .get(&'M')
        .map(String::as_str)
        .unwrap_or("unknown server error");
    ConnectionError::ExecutionFailed {
        sqlstate,
        message: message.to_owned(),
    }
}

fn required_password(target: &PostgresTarget) -> Result<String, ConnectionError> {
    target.password.clone().ok_or(ConnectionError::AuthFailed)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

async fn handle_auth<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
    target: &PostgresTarget,
    scram: &mut Option<ScramClient>,
) -> Result<(), ConnectionError> {
    if payload.len() < 4 {
        return Err(ConnectionError::Protocol(
            "truncated auth message".to_owned(),
        ));
    }
    let code = i32::from_be_bytes(slice4(&payload[0..4])?);
    match code {
        // AuthenticationOk: keep waiting for ReadyForQuery.
        0 => {}
        3 => {
            // AuthenticationCleartextPassword
            let password = required_password(target)?;
            let mut message = password.into_bytes();
            message.push(0);
            write_message(stream, b'p', &message).await?;
        }
        5 => {
            // AuthenticationMD5Password: 4-byte salt follows the code.
            let password = required_password(target)?;
            if payload.len() < 8 {
                return Err(ConnectionError::Protocol("truncated md5 salt".to_owned()));
            }
            let digest = auth::md5_password(&target.user, &password, &payload[4..8]);
            let mut message = digest.into_bytes();
            message.push(0);
            write_message(stream, b'p', &message).await?;
        }
        10 => {
            // AuthenticationSASL: mechanism list follows the code.
            let password = required_password(target)?;
            if !contains(payload, auth::SASL_MECHANISM.as_bytes()) {
                return Err(ConnectionError::Protocol(
                    "no supported SASL mechanism offered".to_owned(),
                ));
            }
            let client = ScramClient::new(&password);
            let sparse_len = client.client_first_bare().len() as i32;
            let mut message = Vec::new();
            message.extend_from_slice(auth::SASL_MECHANISM.as_bytes());
            message.push(0);
            message.extend_from_slice(&sparse_len.to_be_bytes());
            message.extend_from_slice(b"n,,");
            message.extend_from_slice(client.client_first_bare().as_bytes());
            write_message(stream, b'p', &message).await?;
            *scram = Some(client);
        }
        11 => {
            // AuthenticationSASLContinue: server-first-message data.
            let Some(client) = scram.as_mut() else {
                return Err(ConnectionError::Protocol(
                    "unexpected SASLContinue".to_owned(),
                ));
            };
            let final_message = client.client_final_message(&payload[4..])?;
            write_message(stream, b'p', final_message.as_bytes()).await?;
        }
        12 => {
            // AuthenticationSASLFinal: server-final-message data.
            let Some(client) = scram.as_ref() else {
                return Err(ConnectionError::Protocol("unexpected SASLFinal".to_owned()));
            };
            client.verify_server_final(&payload[4..])?;
        }
        other => {
            return Err(ConnectionError::Protocol(format!(
                "unsupported auth code {other}"
            )));
        }
    }
    Ok(())
}

fn apply_parameter_status(params: &mut HashMap<String, String>, payload: &[u8]) {
    let read_cstring = |start: usize| -> Option<(String, usize)> {
        let end = payload
            .get(start..)?
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| start + offset)?;
        Some((
            String::from_utf8_lossy(&payload[start..end]).into_owned(),
            end + 1,
        ))
    };
    let Some((key, next)) = read_cstring(0) else {
        return;
    };
    if let Some((value, _)) = read_cstring(next) {
        params.insert(key, value);
    }
}

/// CommandComplete payload is the tag plus its trailing NUL
/// (`SELECT 2\0`, `INSERT 0 1\0`, `BEGIN\0`).
fn parse_command_tag(payload: &[u8]) -> String {
    let end = payload
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).into_owned()
}

/// Trailing number of the tag when present and entirely decimal
/// (`SELECT 2` -> 2, `INSERT 0 1` -> 1, `BEGIN` -> None).
fn tag_affected_rows(tag: &str) -> Option<i64> {
    tag.rsplit(' ')
        .next()
        .and_then(|token| token.parse::<i64>().ok())
}

/// Row description: column count, then per column `name\0` plus 18 fixed
/// bytes (table oid 4, attr 2, type oid 4, type size 2, modifier 4, format 2).
fn parse_row_description(payload: &[u8]) -> Vec<String> {
    if payload.len() < 2 {
        return Vec::new();
    }
    let count = i16::from_be_bytes([payload[0], payload[1]]);
    let mut columns = Vec::with_capacity(count.max(0) as usize);
    let mut i = 2;
    for _ in 0..count.max(0) {
        if i >= payload.len() {
            break;
        }
        let Some(end_offset) = payload[i..].iter().position(|byte| *byte == 0) else {
            break;
        };
        let end = i + end_offset;
        columns.push(String::from_utf8_lossy(&payload[i..end]).into_owned());
        // name + \0 + 18 fixed bytes; tolerate a truncated descriptor.
        i = end + 1 + 4 + 2 + 4 + 2 + 4 + 2;
        if i > payload.len() {
            break;
        }
    }
    columns
}

/// Data row: column count, then per column an i32 length (-1 = NULL) and the
/// text-format bytes.
fn parse_data_row(payload: &[u8]) -> Result<Vec<Option<String>>, ConnectionError> {
    let count = i16::from_be_bytes(slice2(&payload[0..2])?);
    let mut values = Vec::with_capacity(count.max(0) as usize);
    let mut i = 2;
    for _ in 0..count.max(0) {
        if i + 4 > payload.len() {
            return Err(ConnectionError::Protocol("truncated data row".to_owned()));
        }
        let len = i32::from_be_bytes(slice4(&payload[i..i + 4])?);
        i += 4;
        if len < 0 {
            values.push(None);
            continue;
        }
        let len = len as usize;
        if i + len > payload.len() {
            return Err(ConnectionError::Protocol("truncated data row".to_owned()));
        }
        values.push(Some(
            String::from_utf8_lossy(&payload[i..i + len]).into_owned(),
        ));
        i += len;
    }
    Ok(values)
}

/// RowDescription with the fields the typed flow needs: name plus type OID
/// (table oid, attribute number, type size, type modifier and format code
/// are skipped over).
fn parse_row_description_full(payload: &[u8]) -> Result<Vec<ColumnMeta>, ConnectionError> {
    if payload.len() < 2 {
        return Err(ConnectionError::Protocol(
            "truncated row description".to_owned(),
        ));
    }
    let count = i16::from_be_bytes(slice2(&payload[0..2])?);
    let mut columns = Vec::with_capacity(count.max(0) as usize);
    let mut i = 2;
    for _ in 0..count.max(0) {
        let Some(offset) = payload
            .get(i..)
            .and_then(|rest| rest.iter().position(|byte| *byte == 0))
        else {
            return Err(ConnectionError::Protocol(
                "truncated row description".to_owned(),
            ));
        };
        let end = i + offset;
        let name = String::from_utf8_lossy(&payload[i..end]).into_owned();
        // table oid (4) + attribute (2), then the type oid.
        let type_start = end + 1 + 4 + 2;
        if type_start + 4 > payload.len() {
            return Err(ConnectionError::Protocol(
                "truncated row description".to_owned(),
            ));
        }
        let oid = i32::from_be_bytes(slice4(&payload[type_start..type_start + 4])?);
        columns.push(ColumnMeta { name, oid });
        // type oid (4) + size (2) + modifier (4) + format (2).
        i = type_start + 12;
    }
    Ok(columns)
}

/// ParameterDescription: count plus the server-declared type OID per
/// parameter.
fn parse_parameter_description(payload: &[u8]) -> Result<Vec<i32>, ConnectionError> {
    if payload.len() < 2 {
        return Err(ConnectionError::Protocol(
            "truncated parameter description".to_owned(),
        ));
    }
    let count = i16::from_be_bytes(slice2(&payload[0..2])?) as usize;
    if payload.len() < 2 + count * 4 {
        return Err(ConnectionError::Protocol(
            "truncated parameter description".to_owned(),
        ));
    }
    let mut oids = Vec::with_capacity(count);
    for index in 0..count {
        oids.push(i32::from_be_bytes(slice4(
            &payload[2 + index * 4..6 + index * 4],
        )?));
    }
    Ok(oids)
}

/// Data row with typed values: column count, then per column an i32 length
/// (`-1` = NULL) and the value bytes in the format previously requested for
/// that column.
fn parse_typed_data_row(
    payload: &[u8],
    columns: &[ColumnMeta],
    formats: &[i16],
) -> Result<Vec<Option<TypedValue>>, ConnectionError> {
    if payload.len() < 2 {
        return Err(ConnectionError::Protocol("truncated data row".to_owned()));
    }
    let count = i16::from_be_bytes(slice2(&payload[0..2])?);
    if count.max(0) as usize != columns.len() {
        return Err(ConnectionError::Protocol(
            "data row column count does not match the description".to_owned(),
        ));
    }
    let mut values = Vec::with_capacity(columns.len());
    let mut i = 2;
    for index in 0..columns.len() {
        if i + 4 > payload.len() {
            return Err(ConnectionError::Protocol("truncated data row".to_owned()));
        }
        let len = i32::from_be_bytes(slice4(&payload[i..i + 4])?);
        i += 4;
        if len < 0 {
            values.push(None);
            continue;
        }
        let len = len as usize;
        if i + len > payload.len() {
            return Err(ConnectionError::Protocol("truncated data row".to_owned()));
        }
        let bytes = &payload[i..i + len];
        let decoded = if formats[index] == 1 {
            match types::binary_decode(columns[index].oid, bytes)? {
                Some(value) => value,
                // Defensive: the server overrode our binary request (an
                // extension rewrote the type); fall back to text decoding.
                None => types::text_decode(columns[index].oid, bytes)?,
            }
        } else {
            types::text_decode(columns[index].oid, bytes)?
        };
        values.push(Some(decoded));
        i += len;
    }
    Ok(values)
}

/// Startup negotiation on an established stream: startup packet, auth
/// exchange, parameter capture and the initial transaction status until
/// `ReadyForQuery`.
async fn startup_exchange(
    stream: &mut NetStream,
    target: &PostgresTarget,
) -> Result<(HashMap<String, String>, TxnStatus), ConnectionError> {
    let params: [(&str, Option<&str>); 2] = [
        ("user", Some(target.user.as_str())),
        ("database", target.database.as_deref()),
    ];
    write_startup(stream, &params).await?;

    let mut scram: Option<ScramClient> = None;
    let mut server_params: HashMap<String, String> = HashMap::new();
    // Definite assigned at `Z` before any read through that path.
    let txn_status: TxnStatus;

    loop {
        let (tag, payload) = read_message(stream).await?;
        match tag {
            b'R' => handle_auth(stream, &payload, target, &mut scram).await?,
            b'S' => apply_parameter_status(&mut server_params, &payload),
            b'E' => return Err(error_response(&payload)),
            // BackendKeyData, NoticeResponse, NegotiateProtocolVersion.
            b'K' | b'N' | b'v' => {}
            b'Z' => {
                let byte = payload.first().copied().unwrap_or(b'I');
                txn_status = status_from_byte(byte)?;
                return Ok((server_params, txn_status));
            }
            other => {
                return Err(ConnectionError::Protocol(format!(
                    "unexpected message {other} during startup"
                )));
            }
        }
    }
}

impl Connection {
    /// Dials, negotiates TLS per `ssl_mode`, runs the startup exchange and
    /// authenticates, returning the live connection once `ReadyForQuery`.
    pub async fn connect(target: &PostgresTarget) -> Result<Self, ConnectionError> {
        let mut tcp = TcpStream::connect((target.host.as_str(), target.port))
            .await
            .map_err(|_| io_err())?;

        let mut stream = match target.ssl_mode {
            SslMode::Disable => NetStream::Plain(tcp),
            SslMode::Prefer | SslMode::Require => {
                write_ssl_request(&mut tcp).await?;
                let mut answer = [0u8; 1];
                read_exact(&mut tcp, &mut answer).await?;
                match (answer[0], target.ssl_mode) {
                    (b'S', SslMode::Prefer | SslMode::Require) => tls_upgrade(tcp, target).await?,
                    (b'N', SslMode::Prefer) => NetStream::Plain(tcp),
                    (b'N', _) => {
                        return Err(ConnectionError::Protocol(
                            "server does not support SSL (ssl_mode=require)".to_owned(),
                        ));
                    }
                    (other, _) => {
                        return Err(ConnectionError::Protocol(format!(
                            "invalid SSLRequest answer {other}"
                        )));
                    }
                }
            }
        };
        let (server_params, txn_status) = startup_exchange(&mut stream, target).await?;
        Ok(Self {
            stream,
            server_params,
            txn_status,
            statements: StatementCache::new(STATEMENT_CACHE_MAX),
            next_statement_id: 0,
        })
    }

    /// Simple query protocol (`Query`). Rows are text-format strings; NULL is
    /// `None`. Returns on `ReadyForQuery`; an empty `sql` maps to the
    /// `EmptyQueryResponse` path (used as connection ping).
    pub async fn simple_query(&mut self, sql: &str) -> Result<QueryResult, ConnectionError> {
        let mut payload = sql.as_bytes().to_vec();
        payload.push(0);
        write_message(&mut self.stream, b'Q', &payload).await?;

        let mut result = QueryResult {
            columns: Vec::new(),
            rows: Vec::new(),
        };
        loop {
            let (tag, payload) = read_message(&mut self.stream).await?;
            match tag {
                b'T' => result.columns = parse_row_description(&payload),
                b'D' => result.rows.push(parse_data_row(&payload)?),
                // CommandComplete, EmptyQueryResponse, Notice, ParameterStatus.
                b'C' | b'I' | b'N' | b'S' => {}
                b'E' => return Err(runtime_error_response(&payload)),
                b'Z' => {
                    let byte = payload.first().copied().unwrap_or(b'I');
                    self.txn_status = status_from_byte(byte)?;
                    return Ok(result);
                }
                other => {
                    return Err(ConnectionError::Protocol(format!(
                        "unexpected message {other} during query"
                    )));
                }
            }
        }
    }

    /// Last `ReadyForQuery` transaction status (`I` idle, `T` in
    /// transaction, `E` failed).
    pub fn transaction_status(&self) -> TxnStatus {
        self.txn_status
    }

    /// Runs one control command (`BEGIN`/`COMMIT`/`ROLLBACK`) over the
    /// extended protocol and verifies the returned command tag.
    async fn control_statement(&mut self, expected_tag: &str) -> Result<(), ConnectionError> {
        let result = self.extended_query(expected_tag, &[]).await?;
        match result.command_tag.as_deref() {
            Some(tag) if tag.starts_with(expected_tag) => Ok(()),
            Some(tag) => Err(ConnectionError::Protocol(format!(
                "unexpected {expected_tag} result: {tag}"
            ))),
            None => Err(ConnectionError::Protocol(format!(
                "{expected_tag} did not report a command tag"
            ))),
        }
    }

    /// Explicit transaction control (DBeaver transaction manager analog).
    /// `begin` inside an active transaction only resets it: PostgreSQL
    /// answers with a warning (`NoticeResponse`) and a fresh `BEGIN` tag.
    pub async fn begin(&mut self) -> Result<(), ConnectionError> {
        self.control_statement("BEGIN").await
    }

    pub async fn commit(&mut self) -> Result<(), ConnectionError> {
        self.control_statement("COMMIT").await
    }

    /// Rolls back the current transaction. Also works in the `E` (failed)
    /// state, normalizing the connection back to idle.
    pub async fn rollback(&mut self) -> Result<(), ConnectionError> {
        self.control_statement("ROLLBACK").await
    }

    /// Extended query protocol for one prepared statement with parameters:
    /// `Parse` (unnamed statement, declared OIDs) -> `Bind` (unnamed portal,
    /// binary-format params, text-format results) -> `Describe` portal ->
    /// `Execute` (all rows) -> `Sync`. Errors are collected and reported
    /// after `ReadyForQuery`, leaving the connection reusable (the aborting
    /// implicit transaction rolls back at `Sync`).
    pub async fn extended_query(
        &mut self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<ExtendedResult, ConnectionError> {
        // Parse: [name\0][sql\0][i16 param count][i32 oid per param].
        write_message(
            &mut self.stream,
            b'P',
            &parse_message_payload("", sql, params),
        )
        .await?;

        // Bind: unnamed portal, every parameter binary (1), every result
        // text (0).
        write_message(
            &mut self.stream,
            b'B',
            &bind_message_payload("", "", params, &[0]),
        )
        .await?;

        // Describe portal: returns ParameterDescription + RowDescription
        // (or NoData for non-row statements).
        write_message(&mut self.stream, b'D', b"P\0").await?;

        // Execute: [portal\0][i32 max_rows]; 0 = return every row (no
        // PortalSuspended path).
        let mut execute_payload = vec![0u8];
        execute_payload.extend_from_slice(&0i32.to_be_bytes());
        write_message(&mut self.stream, b'E', &execute_payload).await?;

        write_message(&mut self.stream, b'S', &[]).await?;

        let mut result = ExtendedResult {
            columns: Vec::new(),
            rows: Vec::new(),
            command_tag: None,
            affected_rows: None,
        };
        let mut runtime_error: Option<ConnectionError> = None;
        loop {
            let (tag, payload) = read_message(&mut self.stream).await?;
            match tag {
                // ParseComplete, BindComplete, ParameterDescription.
                b'1' | b'2' | b't' => {}
                b'T' => result.columns = parse_row_description(&payload),
                // NoData for statements that do not return rows.
                b'n' => {}
                b'D' => result.rows.push(parse_data_row(&payload)?),
                // CommandComplete: capture the tag; trailing digits are the
                // affected-rows count.
                b'C' => {
                    result.command_tag = Some(parse_command_tag(&payload));
                    result.affected_rows =
                        result.command_tag.as_deref().and_then(tag_affected_rows);
                }
                // Notice, BackendKeyData, ParameterStatus, NegotiateProtocolVersion.
                b'N' | b'K' | b'S' | b'v' => {}
                b'E' => {
                    // Keep draining until `Z` so the connection stays in a
                    // well-defined state for the next statement.
                    runtime_error = Some(runtime_error_response(&payload));
                }
                b'Z' => {
                    let byte = payload.first().copied().unwrap_or(b'I');
                    self.txn_status = status_from_byte(byte)?;
                    if let Some(error) = runtime_error {
                        return Err(error);
                    }
                    return Ok(result);
                }
                b's' => {
                    return Err(ConnectionError::Protocol(
                        "unexpected PortalSuspended (max_rows=0)".to_owned(),
                    ));
                }
                other => {
                    return Err(ConnectionError::Protocol(format!(
                        "unexpected message {other} during extended query"
                    )));
                }
            }
        }
    }

    /// Typed execution: describes the unnamed statement first
    /// (`Parse -> Describe statement -> Flush`) so column OIDs are known
    /// before `Bind` — cataloged types are requested in binary format (1),
    /// the rest stay text (0). The execution phase is `Bind -> Execute ->
    /// Sync`; the portal does not need a second `Describe`. NULL keeps its
    /// `-1` sentinel; a mid-flow error is drained until `Z` with the
    /// statement closed by `Sync`, so the reconnect is not required.
    pub async fn typed_query(
        &mut self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<TypedResult, ConnectionError> {
        write_message(
            &mut self.stream,
            b'P',
            &parse_message_payload("", sql, params),
        )
        .await?;
        write_message(&mut self.stream, b'D', b"S\0").await?;
        write_message(&mut self.stream, b'H', &[]).await?;

        let mut columns: Vec<ColumnMeta> = Vec::new();
        loop {
            let (tag, payload) = read_message(&mut self.stream).await?;
            match tag {
                // ParseComplete, ParameterDescription.
                b'1' | b't' => {}
                b'T' => {
                    columns = parse_row_description_full(&payload)?;
                    break;
                }
                // NoData for statements that do not return rows.
                b'n' => break,
                // Notice, BackendKeyData, ParameterStatus,
                // NegotiateProtocolVersion.
                b'N' | b'K' | b'S' | b'v' => {}
                b'E' => {
                    // Close the aborted implicit transaction with `Sync`
                    // and drain until `Z` so the connection stays usable.
                    let error = runtime_error_response(&payload);
                    write_message(&mut self.stream, b'S', &[]).await?;
                    let mut runtime_error = Some(error);
                    loop {
                        let (tag, payload) = read_message(&mut self.stream).await?;
                        match tag {
                            b'N' | b'K' | b'S' | b'v' | b'1' | b'2' | b't' | b'C' | b'D' => {}
                            b'Z' => {
                                let byte = payload.first().copied().unwrap_or(b'I');
                                self.txn_status = status_from_byte(byte)?;
                                return Err(runtime_error.take().expect("set above"));
                            }
                            other => {
                                return Err(ConnectionError::Protocol(format!(
                                    "unexpected message {other} after describe error"
                                )));
                            }
                        }
                    }
                }
                other => {
                    return Err(ConnectionError::Protocol(format!(
                        "unexpected message {other} during statement describe"
                    )));
                }
            }
        }

        // Result format per column: binary where the catalog supports it.
        let formats: Vec<i16> = columns
            .iter()
            .map(|column| {
                if types::binary_supported(column.oid) {
                    1
                } else {
                    0
                }
            })
            .collect();

        // Bind: unnamed portal, every parameter binary, result formats
        // following the catalog.
        write_message(
            &mut self.stream,
            b'B',
            &bind_message_payload("", "", params, &formats),
        )
        .await?;

        // Execute: all rows, no PortalSuspended path.
        let mut execute_payload = vec![0u8];
        execute_payload.extend_from_slice(&0i32.to_be_bytes());
        write_message(&mut self.stream, b'E', &execute_payload).await?;
        write_message(&mut self.stream, b'S', &[]).await?;

        let mut result = TypedResult {
            columns,
            rows: Vec::new(),
            command_tag: None,
            affected_rows: None,
        };
        let mut runtime_error: Option<ConnectionError> = None;
        loop {
            let (tag, payload) = read_message(&mut self.stream).await?;
            match tag {
                // ParseComplete, BindComplete, ParameterDescription, NoData,
                // and a portal `Describe` would re-send its row description.
                b'1' | b'2' | b't' | b'n' | b'T' => {}
                b'D' => {
                    let row = parse_typed_data_row(&payload, &result.columns, &formats)?;
                    result.rows.push(row);
                }
                b'C' => {
                    result.command_tag = Some(parse_command_tag(&payload));
                    result.affected_rows =
                        result.command_tag.as_deref().and_then(tag_affected_rows);
                }
                b'N' | b'K' | b'S' | b'v' => {}
                b'E' => {
                    runtime_error = Some(runtime_error_response(&payload));
                }
                b'Z' => {
                    let byte = payload.first().copied().unwrap_or(b'I');
                    self.txn_status = status_from_byte(byte)?;
                    if let Some(error) = runtime_error {
                        return Err(error);
                    }
                    return Ok(result);
                }
                b's' => {
                    return Err(ConnectionError::Protocol(
                        "unexpected PortalSuspended (max_rows=0)".to_owned(),
                    ));
                }
                other => {
                    return Err(ConnectionError::Protocol(format!(
                        "unexpected message {other} during typed query"
                    )));
                }
            }
        }
    }

    /// Prepares a named statement and captures its metadata (DBeaver
    /// prepared-statement reuse analog): `Parse(name) -> Describe
    /// statement(name) -> Sync`. Named statements survive transactions, so
    /// later `Bind`/`Execute`/`Sync` cycles skip the parse entirely;
    /// server-declared parameter OIDs and catalog-driven result formats
    /// are stable across runs. The handle is valid only on connections
    /// that share the session where it was prepared.
    pub async fn prepare(&mut self, name: &str, sql: &str) -> Result<Prepared, ConnectionError> {
        write_message(
            &mut self.stream,
            b'P',
            &parse_message_payload(name, sql, &[]),
        )
        .await?;
        let mut describe_payload = name.as_bytes().to_vec();
        describe_payload.push(0);
        write_message(&mut self.stream, b'D', &describe_payload).await?;
        write_message(&mut self.stream, b'S', &[]).await?;

        let sql_stored = sql.to_owned();
        let mut param_oids: Vec<i32> = Vec::new();
        let mut columns: Vec<ColumnMeta> = Vec::new();
        let mut runtime_error: Option<ConnectionError> = None;
        loop {
            let (tag, payload) = read_message(&mut self.stream).await?;
            match tag {
                // ParseComplete.
                b'1' => {}
                // ParameterDescription: server-declared parameter OIDs.
                b't' => param_oids = parse_parameter_description(&payload)?,
                b'T' => columns = parse_row_description_full(&payload)?,
                // NoData for statements that do not return rows.
                b'n' => {}
                // Notice, BackendKeyData, ParameterStatus,
                // NegotiateProtocolVersion.
                b'N' | b'K' | b'S' | b'v' => {}
                b'E' => {
                    runtime_error = Some(runtime_error_response(&payload));
                }
                b'Z' => {
                    let byte = payload.first().copied().unwrap_or(b'I');
                    self.txn_status = status_from_byte(byte)?;
                    if let Some(error) = runtime_error {
                        return Err(error);
                    }
                    // Result format per column, decided once: binary where
                    // the catalog supports the type.
                    let result_formats: Vec<i16> = columns
                        .iter()
                        .map(|column| {
                            if types::binary_supported(column.oid) {
                                1
                            } else {
                                0
                            }
                        })
                        .collect();
                    return Ok(Prepared {
                        name: name.to_owned(),
                        sql: sql_stored,
                        param_oids,
                        columns,
                        result_formats,
                    });
                }
                other => {
                    return Err(ConnectionError::Protocol(format!(
                        "unexpected message {other} during prepare"
                    )));
                }
            }
        }
    }

    /// Runs one previously prepared statement: `Bind(statement name) ->
    /// Execute -> Sync`. No re-`Parse`, no re-`Describe`: the metadata
    /// captured at prepare time drives the formats and the typed decoding.
    pub async fn run_prepared(
        &mut self,
        prepared: &Prepared,
        params: &[QueryParameter],
    ) -> Result<TypedResult, ConnectionError> {
        write_message(
            &mut self.stream,
            b'B',
            &bind_message_payload("", &prepared.name, params, &prepared.result_formats),
        )
        .await?;

        // Execute: all rows, no PortalSuspended path.
        let mut execute_payload = vec![0u8];
        execute_payload.extend_from_slice(&0i32.to_be_bytes());
        write_message(&mut self.stream, b'E', &execute_payload).await?;
        write_message(&mut self.stream, b'S', &[]).await?;

        let mut result = TypedResult {
            columns: prepared.columns.clone(),
            rows: Vec::new(),
            command_tag: None,
            affected_rows: None,
        };
        let mut runtime_error: Option<ConnectionError> = None;
        loop {
            let (tag, payload) = read_message(&mut self.stream).await?;
            match tag {
                // BindComplete, ParameterDescription, ParseComplete, NoData.
                b'2' | b'1' | b't' | b'n' => {}
                b'D' => {
                    let row = parse_typed_data_row(
                        &payload,
                        &prepared.columns,
                        &prepared.result_formats,
                    )?;
                    result.rows.push(row);
                }
                b'C' => {
                    result.command_tag = Some(parse_command_tag(&payload));
                    result.affected_rows =
                        result.command_tag.as_deref().and_then(tag_affected_rows);
                }
                b'N' | b'K' | b'S' | b'v' => {}
                b'E' => {
                    runtime_error = Some(runtime_error_response(&payload));
                }
                b'Z' => {
                    let byte = payload.first().copied().unwrap_or(b'I');
                    self.txn_status = status_from_byte(byte)?;
                    if let Some(error) = runtime_error {
                        return Err(error);
                    }
                    return Ok(result);
                }
                b's' => {
                    return Err(ConnectionError::Protocol(
                        "unexpected PortalSuspended (max_rows=0)".to_owned(),
                    ));
                }
                other => {
                    return Err(ConnectionError::Protocol(format!(
                        "unexpected message {other} during prepared run"
                    )));
                }
            }
        }
    }

    /// SQL-keyed prepared statement cache hit path: first use prepares and
    /// stores the named statement, later uses bind to the cached handle
    /// directly (no re-parse). Evicted/unbound names stay server-side
    /// until session end; on fatal errors nothing is cached.
    pub async fn cached_query(
        &mut self,
        sql: &str,
        params: &[QueryParameter],
    ) -> Result<TypedResult, ConnectionError> {
        let prepared = if let Some(prepared) = self.statements.get(sql) {
            prepared
        } else {
            self.next_statement_id += 1;
            let name = format!("dbp{}", self.next_statement_id);
            let fresh = self.prepare(&name, sql).await?;
            self.statements.put(fresh.clone());
            fresh
        };
        self.run_prepared(&prepared, params).await
    }

    /// Sends `Terminate` and closes the stream.
    pub async fn terminate(mut self) {
        let _ = write_message(&mut self.stream, b'X', &[]).await;
        // TlsStream carries a close_notify via shutdown; plain TCP is enough.
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut self.stream).await;
    }
}

#[cfg(test)]
mod statement_cache_tests {
    use super::*;

    fn prepared(sql: &str) -> Prepared {
        Prepared {
            name: "dbp1".into(),
            sql: sql.to_owned(),
            param_oids: vec![],
            columns: vec![],
            result_formats: vec![],
        }
    }

    #[test]
    fn cache_evicts_the_least_recently_used_sql() {
        let mut cache = StatementCache::new(2);
        cache.put(prepared("SELECT a"));
        cache.put(prepared("SELECT b"));
        // A touch moves "SELECT a" to most-recent.
        let touched = cache.get("SELECT a").expect("hit");
        assert_eq!(touched.name, "dbp1");
        // The evicted one is "SELECT b", the untouched oldest.
        cache.put(prepared("SELECT c"));
        assert!(cache.get("SELECT b").is_none(), "b must be evicted");
        assert!(cache.get("SELECT a").is_some(), "the touched one survives");
        assert!(cache.get("SELECT c").is_some());
    }

    #[test]
    fn cache_bounded_by_max() {
        let mut cache = StatementCache::new(2);
        for i in 0..5 {
            cache.put(prepared(&format!("SELECT {i}")));
        }
        assert_eq!(cache.entries.len(), 2);
        assert!(cache.get("SELECT 0").is_none());
        assert!(cache.get("SELECT 4").is_some());
    }
}
