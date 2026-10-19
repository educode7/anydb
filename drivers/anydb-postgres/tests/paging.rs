//! Portal paging: `Execute(max_rows > 0)` fetches row batches on the
//! unnamed portal; a suspended portal (`PortalSuspended`) keeps the
//! implicit transaction open and later `Execute` calls (no re-Bind)
//! continue it, with the final batch closed by `Sync`. A describe-phase
//! error drains reusably and leaves no half-open portal behind.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use anydb_postgres::protocol::Connection as WireConnection;
use anydb_postgres::types;
use anydb_shared::ConnectionError;
use anydb_shared::driver::statement::TypedValue;

// ---------- transport helpers (same pattern as prepared.rs) ----------

async fn read_message<S: AsyncRead + std::marker::Unpin>(stream: &mut S) -> (u8, Vec<u8>) {
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).await.expect("tag");
    let len = stream.read_i32().await.expect("length");
    let mut payload = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut payload).await.expect("body");
    (tag[0], payload)
}

async fn send<S: AsyncWrite + std::marker::Unpin>(stream: &mut S, tag: u8, payload: &[u8]) {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(tag);
    frame.extend_from_slice(&(payload.len() as i32 + 4).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await.expect("write");
    stream.flush().await.expect("flush");
}

async fn authentication_ok<S: AsyncWrite + std::marker::Unpin>(stream: &mut S) {
    send(stream, b'R', &0i32.to_be_bytes()).await;
}

async fn ready_for_query<S: AsyncWrite + std::marker::Unpin>(stream: &mut S) {
    send(stream, b'Z', b"I").await;
}

async fn spawn_backend<F, Fut>(handler: F) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        handler(stream).await;
    });
    (address, handle)
}

// ---------- server side assertions ----------

fn cstring(payload: &[u8], start: usize) -> (String, usize) {
    let end = payload[start..]
        .iter()
        .position(|byte| *byte == 0)
        .expect("cstring terminator")
        + start;
    (
        String::from_utf8_lossy(&payload[start..end]).into_owned(),
        end + 1,
    )
}

fn i16_be(payload: &[u8], offset: usize) -> i16 {
    i16::from_be_bytes(payload[offset..offset + 2].try_into().expect("i16"))
}

fn i32_be(payload: &[u8], offset: usize) -> i32 {
    i32::from_be_bytes(payload[offset..offset + 4].try_into().expect("i32"))
}

async fn expect_tag<S: AsyncRead + std::marker::Unpin>(stream: &mut S, tag: u8) -> Vec<u8> {
    let (next, payload) = read_message(stream).await;
    assert_eq!(next, tag, "unexpected message");
    payload
}

/// Asserts the unnamed Parse shape for the paging describe phase.
async fn assert_parse_unnamed(stream: &mut TcpStream, sql: &str) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'P', "expected Parse");
    let (name, next) = cstring(&payload, 0);
    assert_eq!(name, "", "unnamed statement");
    let (parsed_sql, next) = cstring(&payload, next);
    assert_eq!(parsed_sql, sql, "unexpected SQL");
    assert_eq!(i16_be(&payload, next), 0, "no parameter OIDs");
}

async fn assert_describe_statement_unnamed(stream: &mut TcpStream) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'D', "expected Describe");
    assert_eq!(payload, b"S\0", "describe the unnamed statement");
}

/// Asserts the Bind of the paging flow: unnamed portal, no parameters,
/// int8 result requested as binary.
async fn assert_paged_bind(stream: &mut TcpStream) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'B', "expected Bind");
    let (portal, next) = cstring(&payload, 0);
    assert_eq!(portal, "", "unnamed portal");
    let (statement, cursor) = cstring(&payload, next);
    assert_eq!(statement, "", "unnamed statement");
    assert_eq!(i16_be(&payload, cursor), 0, "no parameter formats");
    assert_eq!(i16_be(&payload, cursor + 2), 0, "no parameter values");
    assert_eq!(i16_be(&payload, cursor + 4), 1, "one result format code");
    assert_eq!(
        i16_be(&payload, cursor + 6),
        1,
        "int8 result must be binary"
    );
}

/// Asserts an `Execute` on the unnamed portal with the paged limit.
async fn assert_execute_limit(stream: &mut TcpStream, limit: i32) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'E', "expected Execute");
    let (portal, next) = cstring(&payload, 0);
    assert_eq!(portal, "", "unnamed portal");
    assert_eq!(i32_be(&payload, next), limit, "unexpected max_rows");
}

async fn assert_sync<S: AsyncRead + std::marker::Unpin>(stream: &mut S) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'S', "expected Sync");
    assert!(payload.is_empty());
}

fn row_description_int8() -> Vec<u8> {
    let mut payload = 1i16.to_be_bytes().to_vec();
    payload.extend_from_slice(b"g\0");
    // name + \0 + (table oid 4, attr 2, type oid 4, size 2, modifier 4, format 2).
    payload.extend_from_slice(&[0u8; 6]);
    payload.extend_from_slice(&types::oid::INT8.to_be_bytes());
    payload.extend_from_slice(&[0u8; 8]);
    payload
}

fn typed_data_row_int8(value: i64) -> Vec<u8> {
    let mut payload = 1i16.to_be_bytes().to_vec();
    payload.extend_from_slice(&8i32.to_be_bytes());
    payload.extend_from_slice(&value.to_be_bytes());
    payload
}

fn error_payload(sqlstate: &str, message: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    for (code, value) in [('S', "ERROR"), ('C', sqlstate), ('M', message)] {
        payload.extend_from_slice(format!("{code}{value}").as_bytes());
        payload.push(0);
    }
    payload
}

fn target(address: std::net::SocketAddr) -> anydb_postgres::url::PostgresTarget {
    anydb_postgres::url::PostgresTarget {
        host: address.ip().to_string(),
        port: address.port(),
        user: "user".to_owned(),
        password: None,
        database: Some("db".to_owned()),
        ssl_mode: anydb_postgres::url::SslMode::default(),
        ssl_root_cert: None,
    }
}

// ---------- paging flows ----------

/// Six rows streamed in three batches of two: the first call runs the
/// full describe + bind + execute(limit) flow, the suspends re-execute
/// the same portal (no re-Bind), and the final batch closes with Sync.
async fn paged_batches_server(mut stream: TcpStream) {
    let len = stream.read_u32().await.expect("startup length");
    let mut startup = vec![0u8; len as usize - 4];
    stream.read_exact(&mut startup).await.expect("startup body");
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    // Cycle 1: describe phase, then bind + execute(2) suspended.
    assert_parse_unnamed(&mut stream, "SELECT g").await;
    assert_describe_statement_unnamed(&mut stream).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b't', &0i16.to_be_bytes()).await;
    send(&mut stream, b'T', &row_description_int8()).await;
    assert_paged_bind(&mut stream).await;
    assert_execute_limit(&mut stream, 2).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'2', &[]).await;
    send(&mut stream, b'D', &typed_data_row_int8(0)).await;
    send(&mut stream, b'D', &typed_data_row_int8(1)).await;
    send(&mut stream, b's', &[]).await; // PortalSuspended.

    // Cycle 2: continue re-executes the same suspended portal.
    assert_execute_limit(&mut stream, 2).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'D', &typed_data_row_int8(2)).await;
    send(&mut stream, b'D', &typed_data_row_int8(3)).await;
    send(&mut stream, b's', &[]).await;

    // Cycle 3: the final batch completes the portal; Sync closes all.
    assert_execute_limit(&mut stream, 2).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'D', &typed_data_row_int8(4)).await;
    send(&mut stream, b'D', &typed_data_row_int8(5)).await;
    send(&mut stream, b'C', b"SELECT 6\0").await;
    assert_sync(&mut stream).await;
    send(&mut stream, b'Z', b"I").await;
}

#[tokio::test]
async fn paged_portal_streams_rows_in_batches() {
    let (address, server) = spawn_backend(paged_batches_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");

    let first = connection
        .query_page_start("SELECT g", &[], 2)
        .await
        .expect("first batch");
    assert!(first.suspended, "suspends after two rows");
    assert_eq!(
        first
            .result
            .columns
            .iter()
            .map(|column| column.name.clone())
            .collect::<Vec<_>>(),
        vec!["g"]
    );
    assert_eq!(
        first.result.rows,
        vec![
            vec![Some(TypedValue::Int8(0))],
            vec![Some(TypedValue::Int8(1))],
        ]
    );
    assert_eq!(first.result.command_tag, None);
    assert_eq!(first.result.affected_rows, None);

    let second = connection
        .query_page_continue(2)
        .await
        .expect("second batch");
    assert!(second.suspended);
    assert_eq!(
        second.result.rows,
        vec![
            vec![Some(TypedValue::Int8(2))],
            vec![Some(TypedValue::Int8(3))],
        ]
    );
    assert_eq!(second.result.command_tag, None);

    let last = connection.query_page_continue(2).await.expect("last batch");
    assert!(!last.suspended, "portal completed");
    assert_eq!(
        last.result.rows,
        vec![
            vec![Some(TypedValue::Int8(4))],
            vec![Some(TypedValue::Int8(5))],
        ]
    );
    assert_eq!(last.result.command_tag.as_deref(), Some("SELECT 6"));
    assert_eq!(last.result.affected_rows, Some(6));

    connection.terminate().await;
    server.await.expect("server task");
}

/// A describe-phase error closes the implicit transaction with Sync,
/// the connection reports no suspended portal, and a fresh paging start
/// runs the complete flow to completion.
async fn describe_error_recovery_server(mut stream: TcpStream) {
    let len = stream.read_u32().await.expect("startup length");
    let mut startup = vec![0u8; len as usize - 4];
    stream.read_exact(&mut startup).await.expect("startup body");
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    // Cycle 1: the describe fails.
    assert_parse_unnamed(&mut stream, "SELECT g").await;
    assert_describe_statement_unnamed(&mut stream).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(
        &mut stream,
        b'E',
        &error_payload("25P02", "current transaction is aborted"),
    )
    .await;
    assert_sync(&mut stream).await;
    send(&mut stream, b'Z', b"E").await;

    // Cycle 2: the retry runs the complete paged flow.
    assert_parse_unnamed(&mut stream, "SELECT g").await;
    assert_describe_statement_unnamed(&mut stream).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b't', &0i16.to_be_bytes()).await;
    send(&mut stream, b'T', &row_description_int8()).await;
    assert_paged_bind(&mut stream).await;
    assert_execute_limit(&mut stream, 2).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'2', &[]).await;
    send(&mut stream, b'D', &typed_data_row_int8(0)).await;
    send(&mut stream, b'D', &typed_data_row_int8(1)).await;
    send(&mut stream, b'C', b"SELECT 2\0").await;
    assert_sync(&mut stream).await;
    send(&mut stream, b'Z', b"I").await;
}

#[tokio::test]
async fn describe_error_recovers_for_the_next_page() {
    let (address, server) = spawn_backend(describe_error_recovery_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");

    let error = connection
        .query_page_start("SELECT g", &[], 2)
        .await
        .expect_err("describe must fail");
    assert!(matches!(error, ConnectionError::ExecutionFailed { .. }));

    let none = connection
        .query_page_continue(2)
        .await
        .expect_err("no portal must be open after the error");
    assert!(matches!(
        none,
        ConnectionError::Protocol(message) if message == "no suspended portal"
    ));

    let page = connection
        .query_page_start("SELECT g", &[], 2)
        .await
        .expect("retry completes");
    assert!(!page.suspended);
    assert_eq!(
        page.result.rows,
        vec![
            vec![Some(TypedValue::Int8(0))],
            vec![Some(TypedValue::Int8(1))],
        ]
    );
    assert_eq!(page.result.command_tag.as_deref(), Some("SELECT 2"));
    assert_eq!(page.result.affected_rows, Some(2));

    connection.terminate().await;
    server.await.expect("server task");
}

/// A mid-batch error on a CONTINUE aborts the implicit transaction,
/// which destroys the suspended portal: the next continue fails
/// locally, and a fresh paging start runs the complete flow on the
/// same connection.
async fn mid_batch_error_disposal_server(mut stream: TcpStream) {
    let len = stream.read_u32().await.expect("startup length");
    let mut startup = vec![0u8; len as usize - 4];
    stream.read_exact(&mut startup).await.expect("startup body");
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    // Cycle 1: batch one suspends, the continuation fails mid-batch.
    assert_parse_unnamed(&mut stream, "SELECT g").await;
    assert_describe_statement_unnamed(&mut stream).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b't', &0i16.to_be_bytes()).await;
    send(&mut stream, b'T', &row_description_int8()).await;
    assert_paged_bind(&mut stream).await;
    assert_execute_limit(&mut stream, 1).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'2', &[]).await;
    send(&mut stream, b'D', &typed_data_row_int8(0)).await;
    send(&mut stream, b's', &[]).await; // PortalSuspended.

    // The suspended portal is re-executed; the next row fails.
    assert_execute_limit(&mut stream, 1).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'D', &typed_data_row_int8(1)).await;
    send(
        &mut stream,
        b'E',
        &error_payload("22P02", "invalid input syntax at row three"),
    )
    .await;
    // The driver closes the aborted implicit transaction with Sync.
    assert_sync(&mut stream).await;
    send(&mut stream, b'Z', b"I").await;

    // Cycle 2: a fresh paging start runs the complete flow (no stale
    // Execute may appear between the two cycles).
    assert_parse_unnamed(&mut stream, "SELECT g").await;
    assert_describe_statement_unnamed(&mut stream).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b't', &0i16.to_be_bytes()).await;
    send(&mut stream, b'T', &row_description_int8()).await;
    assert_paged_bind(&mut stream).await;
    assert_execute_limit(&mut stream, 1).await;
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'2', &[]).await;
    send(&mut stream, b'D', &typed_data_row_int8(9)).await;
    send(&mut stream, b'C', b"SELECT 1\0").await;
    assert_sync(&mut stream).await;
    send(&mut stream, b'Z', b"I").await;
}

#[tokio::test]
async fn mid_batch_error_disposes_the_portal_state() {
    let (address, server) = spawn_backend(mid_batch_error_disposal_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");

    let first = connection
        .query_page_start("SELECT g", &[], 1)
        .await
        .expect("first batch");
    assert!(first.suspended);
    assert_eq!(first.result.rows, vec![vec![Some(TypedValue::Int8(0))]]);

    let failed = connection
        .query_page_continue(1)
        .await
        .expect_err("mid-batch error");
    assert!(matches!(failed, ConnectionError::ExecutionFailed { .. }));

    // The aborted transaction destroyed the portal: continuing fails
    // locally, with no wire traffic (the fake reaches cycle 2 directly).
    let stale = connection
        .query_page_continue(1)
        .await
        .expect_err("no portal may survive the aborted transaction");
    assert!(matches!(
        stale,
        ConnectionError::Protocol(message) if message == "no suspended portal"
    ));

    // Recovery: a fresh page start completes on the same connection.
    let recovered = connection
        .query_page_start("SELECT g", &[], 1)
        .await
        .expect("recovery page");
    assert!(!recovered.suspended);
    assert_eq!(recovered.result.rows, vec![vec![Some(TypedValue::Int8(9))]]);

    connection.terminate().await;
    server.await.expect("server task");
}
