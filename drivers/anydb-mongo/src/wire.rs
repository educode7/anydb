//! Mongo wire client over OP_MSG: `hello` handshake (_learned_
//! `saslSupportedMechs`), SCRAM authentication, one-shot `find`,
//! `ping` and cursor-id batch paging. One `Connection` drives exactly
//! one transport (plain TCP or rustls TLS started from the first
//! byte); concurrency is serialized one level up (the driver facade's
//! tokio mutex), so all methods take `&mut self`.
//!
//! Deliberate scope: `ssl_mode` is only `disable`/`require` (mongo has
//! no negotiation probe — see the `SslMode` doc), certificates are
//! always verified, and paging keeps exactly one live cursor, killing
//! it best-effort on abandon (server TTL is the last resort).

use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

use crate::bson::{self, Bson, Document};
use crate::op_msg::OpMsg;
use crate::scram::{Mechanism, ScramClient};
use crate::uri::{MongoTarget, SslMode};
use anydb_shared::ConnectionError;
use anydb_shared::driver::statement::TypedStatementResult;

fn protocol(message: String) -> ConnectionError {
    ConnectionError::Protocol(format!("mongo wire: {message}"))
}

/// One client transport: raw TCP or the TLS stream upgraded from the
/// first byte (mongo has no SSLRequest dance; a `require` target is
/// TLS-wrapped before the first `hello` byte leaves).
#[derive(Debug)]
enum NetStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for NetStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for NetStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, bufs),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, bufs),
        }
    }

    #[inline]
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }
}

fn int32_field(document: &Document, key: &str) -> i32 {
    match document.iter().find(|(field_key, _)| field_key == key) {
        Some((_, Bson::Int32(value))) => *value,
        Some((_, Bson::Int64(value))) => *value as i32,
        _ => 0,
    }
}

#[derive(Debug)]
pub struct Connection {
    stream: NetStream,
    next_request_id: i32,
    server_version: String,
    /// The one suspended cursor (`getMore` paging); `None` when no
    /// paging flow is half-open. One cursor at a time keeps the state
    /// machine as simple as the postgres portal does.
    open_cursor: Option<OpenCursor>,
}

/// Frozen identity of a suspended cursor: the server-side id (an
/// opaque i64), the collection for `killCursors` on abandon, and the
/// documents fetched before the pending batch (the final `find N` tag).
#[derive(Debug, Clone, PartialEq)]
struct OpenCursor {
    id: i64,
    collection: String,
    docs_before: i64,
}

impl Connection {
    /// Dial (plain TCP or TLS per `ssl_mode`) + `hello` handshake +
    /// optional SCRAM. A URL without credentials connects anonymously
    /// (SCRAM is skipped entirely).
    pub async fn connect(target: &MongoTarget) -> Result<Self, ConnectionError> {
        let stream = match target.ssl_mode {
            SslMode::Disable => NetStream::Plain(
                TcpStream::connect((target.host.as_str(), target.port))
                    .await
                    .map_err(|_| ConnectionError::NetworkFailure)?,
            ),
            SslMode::Require => NetStream::Tls(Box::new(tls_connect(target).await?)),
        };

        let mut connection = Self {
            stream,
            next_request_id: 1,
            server_version: "unknown".to_owned(),
            open_cursor: None,
        };

        let mut handshake = Document::from(vec![
            ("hello".to_owned(), Bson::Int32(1)),
            (
                "client".to_owned(),
                Bson::Document(Document::from(vec![
                    (
                        "driver".to_owned(),
                        Bson::Document(Document::from(vec![
                            ("name".to_owned(), Bson::String("anydb-mongo".to_owned())),
                            (
                                "version".to_owned(),
                                Bson::String(env!("CARGO_PKG_VERSION").to_owned()),
                            ),
                        ])),
                    ),
                    ("os".to_owned(), Bson::Document(Document::new())),
                    (
                        "platform".to_owned(),
                        Bson::String(env!("CARGO_PKG_VERSION").to_owned()),
                    ),
                ])),
            ),
        ]);
        if let Some(user) = &target.user {
            handshake.push((
                "saslSupportedMechs".to_owned(),
                Bson::String(format!("{}.{}", target.auth_db, user)),
            ));
        }
        let reply = connection.command(&handshake).await?;
        if let Some((_, Bson::String(version))) = reply.iter().find(|(key, _)| key == "version") {
            connection.server_version = version.clone();
        }

        if let Some(user) = &target.user {
            let Some(password) = &target.password else {
                return Err(protocol(
                    "SCRAM needs a password (URL or properties) for the target user".to_owned(),
                ));
            };
            let offered = offered_mechanisms(&reply);
            let mechanism = Mechanism::negotiate(offered.as_deref())?;
            connection.authenticate(mechanism, user, password).await?;
        }
        Ok(connection)
    }

    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// One round-trip command: encode OP_MSG, read the reply, require
    /// `ok: 1`, map mongo error payloads onto the shared error type
    /// (code 18 = AuthenticationFailed -> `AuthFailed`).
    async fn command(&mut self, body: &Document) -> Result<Document, ConnectionError> {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        let frame = OpMsg::encode(request_id, body)?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|_| ConnectionError::NetworkFailure)?;
        let reply = OpMsg::read(&mut self.stream).await?;
        if reply.response_to != request_id {
            return Err(protocol(format!(
                "reply answers request {} while {} was in flight",
                reply.response_to, request_id
            )));
        }
        match ok_status(&reply.body) {
            Some(true) => Ok(reply.body),
            Some(false) => Err(command_error(&reply.body)),
            None => Err(protocol("reply lacks an 'ok' status field".to_owned())),
        }
    }

    /// SCRAM over `saslStart` / `saslContinue`. Mongo completes the
    /// client-final round in one extra `saslContinue`; the payload of
    /// its answer carries the server-final signature, verified locally
    /// against the RFC auth-message chain.
    async fn authenticate(
        &mut self,
        mechanism: Mechanism,
        user: &str,
        password: &str,
    ) -> Result<(), ConnectionError> {
        let mut scram = ScramClient::new(mechanism, user, password);
        let start = Document::from(vec![
            ("saslStart".to_owned(), Bson::Int32(1)),
            (
                "mechanism".to_owned(),
                Bson::String(mechanism.name().to_owned()),
            ),
            (
                "payload".to_owned(),
                Bson::Binary(scram.client_first().into_bytes()),
            ),
        ]);
        let reply = self.command(&start).await?;
        scram.server_first(&reply_payload(&reply)?)?;
        let conversation_id = int32_field(&reply, "conversationId");

        let final_payload = scram.client_final()?;
        let step = Document::from(vec![
            ("saslContinue".to_owned(), Bson::Int32(1)),
            ("conversationId".to_owned(), Bson::Int32(conversation_id)),
            (
                "payload".to_owned(),
                Bson::Binary(final_payload.into_bytes()),
            ),
        ]);
        let answer = self.command(&step).await?;
        let payload = reply_payload(&answer)?;
        let done = matches!(
            answer
                .iter()
                .find(|(key, _)| key == "done")
                .map(|(_, value)| value),
            Some(Bson::Boolean(true)) | Some(Bson::Int32(1)) | Some(Bson::Int64(1))
        );
        if !done {
            return Err(protocol(
                "server asked for unsupported extra SCRAM rounds".to_owned(),
            ));
        }
        scram.server_final(&payload)
    }

    /// Fetch-all `find`: single batch, cursor closed by the server.
    /// Internally the degenerate `limit = 0` case of `find_page_start`.
    pub async fn find(&mut self, collection: &str) -> Result<Vec<Document>, ConnectionError> {
        let page = self.find_page_start(collection, 0).await?;
        debug_assert!(!page.suspended);
        Ok(page.documents)
    }

    /// Cursor paging (the mongo analog of the postgres portal flow):
    /// `find` with `batchSize = limit` returns a `firstBatch`; while the
    /// reply carries a non-zero `cursor.id` the paging flow suspends and
    /// `find_page_continue` fetches the next batch with `getMore`. The
    /// final (drained) batch completes the flow.
    ///
    /// `limit = 0` degenerates to fetch-all (`singleBatch: true`, the
    /// exact server semantics of "no cursor"): there is no postgres
    /// `Execute(0)` analog because the server default batch size would
    /// suspend anyway.
    pub async fn find_page_start(
        &mut self,
        collection: &str,
        limit: i32,
    ) -> Result<CursorPage, ConnectionError> {
        if limit < 0 {
            return Err(protocol("negative batch size limit".to_owned()));
        }
        // An abandoned suspended cursor is killed best-effort before a
        // new flow starts (unlike the postgres abandoned portal, a
        // rejected killCursors cannot desynchronize the request/reply
        // framing, so only wire failures propagate).
        self.close_open_cursor().await?;

        let mut command = Document::from(vec![
            ("find".to_owned(), Bson::String(collection.to_owned())),
            ("filter".to_owned(), Bson::Document(Document::new())),
        ]);
        if limit == 0 {
            // Fetch-all: one batch, server closes the cursor.
            command.push(("singleBatch".to_owned(), Bson::Boolean(true)));
        } else {
            command.push(("batchSize".to_owned(), Bson::Int32(limit)));
        }
        let reply = self.command(&command).await?;
        let cursor = parse_cursor(&reply, "find", "firstBatch")?;
        let documents = batch_documents(&cursor.batch, "firstBatch")?;
        let collected = i64::try_from(documents.len())
            .map_err(|_| protocol("batch size exceeds i64".to_owned()))?;
        if cursor.id != 0 && limit == 0 {
            // A server violating singleBatch (or an unsupported legacy
            // behavior): the one-shot contract has no cursor to track.
            return Err(protocol(format!(
                "singleBatch find returned an open cursor ({:#x})",
                cursor.id
            )));
        }
        if cursor.id == 0 {
            return Ok(CursorPage {
                documents,
                suspended: false,
                total: collected,
            });
        }
        self.open_cursor = Some(OpenCursor {
            id: cursor.id,
            collection: collection.to_owned(),
            docs_before: collected,
        });
        Ok(CursorPage {
            documents,
            suspended: true,
            total: collected,
        })
    }

    /// Fetches the next batch of the suspended cursor via `getMore`;
    /// a drained reply (cursor id back to 0) completes the flow and
    /// releases the local cursor state. Errors when no paging flow is
    /// half-open. The batch size is fixed at `find_page_start`: mongo
    /// `getMore` allows re-sizing but the streaming contract stays
    /// constant (unlike the postgres `Execute` whose per-call limit is
    /// protocol-mandatory).
    pub async fn find_page_continue(&mut self) -> Result<CursorPage, ConnectionError> {
        let open = self
            .open_cursor
            .clone()
            .ok_or_else(|| protocol("no suspended cursor".to_owned()))?;
        let command = Document::from(vec![
            ("getMore".to_owned(), Bson::Int64(open.id)),
            (
                "collection".to_owned(),
                Bson::String(open.collection.clone()),
            ),
        ]);
        let reply = match self.command(&command).await {
            Ok(reply) => reply,
            Err(error) => {
                // A failed flow clears the local state: the wire survived
                // (the error is mapped and carries no residual framing),
                // and the abandoned server cursor dies by TTL expiry.
                // The next start cannot kill what it does not track —
                // documented tradeoff of the best-effort policy.
                self.open_cursor = None;
                return Err(error);
            }
        };
        let cursor = parse_cursor(&reply, "getMore", "nextBatch")?;
        // Mongo continuity: the reply keeps the same cursor id while the
        // cursor stays open, and DRAINS it to 0 on the final (drained)
        // batch; anything else is a protocol violation.
        if cursor.id != open.id && cursor.id != 0 {
            self.open_cursor = None;
            return Err(protocol(format!(
                "getMore returned cursor id {:#x} while {:#x} was suspended",
                cursor.id, open.id
            )));
        }
        let documents = batch_documents(&cursor.batch, "nextBatch")?;
        let batch = i64::try_from(documents.len())
            .map_err(|_| protocol("batch size exceeds i64".to_owned()))?;
        let total = open.docs_before + batch;
        if cursor.id == 0 {
            self.open_cursor = None;
            return Ok(CursorPage {
                documents,
                suspended: false,
                total,
            });
        }
        self.open_cursor = Some(OpenCursor {
            docs_before: total,
            ..open
        });
        Ok(CursorPage {
            documents,
            suspended: true,
            total,
        })
    }

    /// Kills the suspended cursor, if any. Best-effort for command-level
    /// failures (the server TTL expiry collects an abandoned cursor
    /// anyway); wire-level failures propagate, they mean a dead
    /// transport.
    async fn close_open_cursor(&mut self) -> Result<(), ConnectionError> {
        let Some(open) = self.open_cursor.take() else {
            return Ok(());
        };
        let command = Document::from(vec![
            ("killCursors".to_owned(), Bson::String(open.collection)),
            (
                "cursors".to_owned(),
                Bson::Array(vec![Bson::Int64(open.id)]),
            ),
        ]);
        // Command failure (dead id, namespace mismatch) leaves no wire
        // residue: swallow it; every other error class still aborts.
        if let Err(error) = self.command(&command).await
            && !matches!(
                error,
                ConnectionError::ExecutionFailed { .. } | ConnectionError::Protocol(_)
            )
        {
            return Err(error);
        }
        Ok(())
    }

    /// Keepalive command (`{ping: 1}`), the whole driver surface the
    /// connection lifecycle needs.
    pub async fn ping(&mut self) -> Result<(), ConnectionError> {
        let command = Document::from(vec![("ping".to_owned(), Bson::Int32(1))]);
        self.command(&command).await.map(|_| ())
    }

    /// Closes the transport: best-effort cursor kill first (mongo has
    /// no close acknowledge like the postgres X message).
    pub async fn terminate(mut self) {
        let _ = self.close_open_cursor().await;
    }
}

/// One batch of a cursor-paged find (the mongo analog of the postgres
/// `TypedPage`): the raw documents of this batch, whether the cursor
/// stays suspended for a `find_page_continue`, and the number of
/// documents collected SO FAR including this batch (the typed surface
/// renders the final `find N` tag from it — mongo replies carry no
/// server-side total like the postgres `CommandComplete`).
#[derive(Debug, Clone, PartialEq)]
pub struct CursorPage {
    /// The documents of this batch only (typed rows are rendered one
    /// level up, per batch: mongo is schemaless and unlike the postgres
    /// portal the columns are not frozen across batches).
    pub documents: Vec<Document>,
    /// `true` while the cursor id is non-zero and `find_page_continue`
    /// must be called for the next batch.
    pub suspended: bool,
    /// Documents collected so far including this batch.
    pub total: i64,
}

/// Typed presentation of one paged batch (postgres `TypedPage` shape):
/// rows through the shared `TypedValue` contract, the `find N` command
/// tag only on the final (drained) batch.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedPage {
    pub result: TypedStatementResult,
    /// `true` while `query_page_continue` has more batches.
    pub suspended: bool,
}

/// Assembles the typed view of a raw batch: per-batch columns (mongo
/// is schemaless), command tag / affected rows only when drained.
pub fn typed_page(page: &CursorPage) -> TypedPage {
    let result = if page.suspended {
        bson::documents_to_result(&page.documents, None, None)
    } else {
        bson::documents_to_result(
            &page.documents,
            Some(&format!("find {}", page.total)),
            Some(page.total),
        )
    };
    TypedPage {
        result,
        suspended: page.suspended,
    }
}

/// Server-side cursor identity of a reply: the opaque id and the batch
/// array (named `firstBatch` on find, `nextBatch` on getMore).
struct ReplyCursor {
    id: i64,
    batch: Vec<Bson>,
}

fn batch_documents(batch: &[Bson], name: &str) -> Result<Vec<Document>, ConnectionError> {
    batch
        .iter()
        .map(|entry| match entry {
            Bson::Document(document) => Ok(document.clone()),
            other => Err(protocol(format!(
                "{name} entry is not a document: {other:?}"
            ))),
        })
        .collect()
}

/// Extracts the `cursor` document of a find/getMore reply: the opaque
/// id (Int64, with an Int32 tolerance for relaxed servers) and the
/// batch array named `batch_name` (`firstBatch` on find, `nextBatch`
/// on getMore).
fn parse_cursor(
    reply: &Document,
    context: &str,
    batch_name: &str,
) -> Result<ReplyCursor, ConnectionError> {
    let Some((_, Bson::Document(cursor))) = reply.iter().find(|(key, _)| key == "cursor") else {
        return Err(protocol(format!("{context} reply lacks a cursor document")));
    };
    let id = match cursor.iter().find(|(key, _)| key == "id").map(|(_, v)| v) {
        Some(Bson::Int64(id)) => *id,
        Some(Bson::Int32(id)) => i64::from(*id),
        Some(other) => return Err(protocol(format!("cursor id is not an integer: {other:?}"))),
        None => return Err(protocol("cursor lacks an id field".to_owned())),
    };
    let batch = match cursor
        .iter()
        .find(|(key, _)| key == batch_name)
        .map(|(_, v)| v)
    {
        Some(Bson::Array(batch)) => batch.clone(),
        Some(other) => return Err(protocol(format!("cursor batch is not an array: {other:?}"))),
        None => return Err(protocol(format!("cursor lacks a {batch_name} array"))),
    };
    Ok(ReplyCursor { id, batch })
}

/// Builds the rustls client config: OS roots by default, PEM file
/// override with `ssl_root_cert`. Certificate verification is always on.
fn tls_client_config(
    target: &MongoTarget,
) -> Result<std::sync::Arc<ClientConfig>, ConnectionError> {
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
    Ok(std::sync::Arc::new(config))
}

/// TCP dial + TLS handshake from the very first byte (there is no
/// plaintext preamble: the listener on the other side is a TLS server
/// already). Always full certificate verification.
async fn tls_connect(
    target: &MongoTarget,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ConnectionError> {
    let connector = TlsConnector::from(tls_client_config(target)?);
    let server_name = ServerName::try_from(target.host.clone()).map_err(|_| {
        ConnectionError::Protocol(format!("invalid TLS server name: {}", target.host))
    })?;
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|_| ConnectionError::NetworkFailure)?;
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|error| ConnectionError::Protocol(format!("TLS handshake failed: {error}")))?;
    Ok(tls_stream)
}

fn offered_mechanisms(reply: &Document) -> Option<Vec<String>> {
    match reply.iter().find(|(key, _)| key == "saslSupportedMechs") {
        Some((_, Bson::Array(names))) => Some(
            names
                .iter()
                .filter_map(|name| match name {
                    Bson::String(text) => Some(text.clone()),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

fn reply_payload(reply: &Document) -> Result<Vec<u8>, ConnectionError> {
    match reply.iter().find(|(key, _)| key == "payload") {
        Some((_, Bson::Binary(bytes))) => Ok(bytes.clone()),
        Some((_, other)) => Err(protocol(format!("SCRAM payload is not binary: {other:?}"))),
        None => Err(protocol("SCRAM reply lacks a payload".to_owned())),
    }
}

fn ok_status(document: &Document) -> Option<bool> {
    let (_, status) = document.iter().find(|(key, _)| key == "ok")?;
    match status {
        Bson::Double(number) => Some(*number == 1.0),
        Bson::Int32(number) => Some(*number == 1),
        Bson::Int64(number) => Some(*number == 1),
        _ => None,
    }
}

fn command_error(document: &Document) -> ConnectionError {
    let code = match document
        .iter()
        .find(|(key, _)| key == "code")
        .map(|(_, v)| v)
    {
        Some(Bson::Int32(code)) => Some(*code),
        Some(Bson::Int64(code)) => Some(*code as i32),
        _ => None,
    };
    let message = match document.iter().find(|(key, _)| key == "errmsg") {
        Some((_, Bson::String(text))) => text.clone(),
        _ => "unknown".to_owned(),
    };
    if code == Some(18) {
        return ConnectionError::AuthFailed;
    }
    match code {
        Some(code) => ConnectionError::ExecutionFailed {
            sqlstate: None,
            message: format!("mongo command failed (code {code}): {message}"),
        },
        None => ConnectionError::ExecutionFailed {
            sqlstate: None,
            message: format!("mongo command failed: {message}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_parsing_covers_ok_shapes() {
        assert_eq!(ok_status(&status(1.0)), Some(true));
        assert_eq!(ok_status(&status(0.0)), Some(false));
        assert_eq!(
            ok_status(&Document::from(vec![("ok".to_owned(), Bson::Int32(1))])),
            Some(true)
        );
        assert_eq!(
            ok_status(&Document::from(vec![("ok".to_owned(), Bson::Int64(0))])),
            Some(false)
        );
        assert_eq!(
            ok_status(&Document::from(vec![("ok".to_owned(), Bson::Int32(5))])),
            Some(false)
        );
        assert_eq!(ok_status(&Document::new()), None);
    }

    fn status(ok: f64) -> Document {
        Document::from(vec![("ok".to_owned(), Bson::Double(ok))])
    }

    #[test]
    fn errors_map_code_18_to_auth_failed() {
        let error = command_error(&Document::from(vec![
            ("ok".to_owned(), Bson::Double(0.0)),
            ("code".to_owned(), Bson::Int32(18)),
            (
                "errmsg".to_owned(),
                Bson::String("Authentication failed.".to_owned()),
            ),
        ]));
        assert_eq!(error, ConnectionError::AuthFailed);

        let error = command_error(&Document::from(vec![
            ("ok".to_owned(), Bson::Double(0.0)),
            ("code".to_owned(), Bson::Int64(256)),
            ("errmsg".to_owned(), Bson::String("boom".to_owned())),
        ]));
        assert!(matches!(
            error,
            ConnectionError::ExecutionFailed { sqlstate: None, .. }
        ));
    }
}
