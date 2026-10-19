//! Extended query protocol integration: loopback backends verify the exact
//! wire sequence (Parse -> Bind -> Describe -> Execute -> Sync), the
//! binary-format parameter encodings and the text-format result path, plus
//! runtime-error mapping and connection reuse after a failed statement.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use anydb_postgres::PostgresDriver;
use anydb_postgres::protocol::Connection as WireConnection;
use anydb_shared::ConnectionError;
use anydb_shared::driver::spi::{Driver, OpenRequest};
use anydb_shared::driver::statement::QueryParameter;

// ---------- transport helpers (same pattern as protocol.rs / tls.rs) ----------

async fn read_startup<S: AsyncRead + std::marker::Unpin>(stream: &mut S) -> i32 {
    let len = stream.read_i32().await.expect("startup length");
    let mut payload = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut payload).await.expect("startup body");
    i32::from_be_bytes(payload[0..4].try_into().expect("version"))
}

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

/// ReadyForQuery while inside a transaction (after BEGIN).
async fn ready_for_query_in_txn<S: AsyncWrite + std::marker::Unpin>(stream: &mut S) {
    send(stream, b'Z', b"T").await;
}

/// ReadyForQuery in the aborted-transaction state (after a runtime error).
async fn ready_for_query_aborted<S: AsyncWrite + std::marker::Unpin>(stream: &mut S) {
    send(stream, b'Z', b"E").await;
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

// ---------- extended-protocol server side assertions ----------

/// Reads one frontend cstring inside a payload and returns it plus the next
/// offset.
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

/// Asserts the Parse message shape: unnamed statement, the expected SQL and
/// the declared type OIDs.
async fn assert_parse<S: AsyncRead + std::marker::Unpin>(stream: &mut S, sql: &str, oids: &[i32]) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'P', "expected Parse");
    let (name, next) = cstring(&payload, 0);
    assert_eq!(name, "", "unnamed statement");
    let (parsed_sql, next) = cstring(&payload, next);
    assert_eq!(parsed_sql, sql, "unexpected SQL");
    assert_eq!(i16_be(&payload, next), oids.len() as i16, "param count");
    for (index, oid) in oids.iter().enumerate() {
        let offset = next + 2 + index * 4;
        assert_eq!(i32_be(&payload, offset), *oid, "param {index} OID");
    }
}

/// Asserts the Bind message shape: unnamed portal/statement, the declared
/// binary format for every parameter and the exact value bytes
/// (`None` = NULL: negative length, no value bytes).
async fn assert_bind<S: AsyncRead + std::marker::Unpin>(stream: &mut S, values: &[Option<&[u8]>]) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'B', "expected Bind");
    let (portal, next) = cstring(&payload, 0);
    assert_eq!(portal, "", "unnamed portal");
    let (statement, mut cursor) = cstring(&payload, next);
    assert_eq!(statement, "", "unnamed statement");

    let formats = i16_be(&payload, cursor);
    assert_eq!(formats, values.len() as i16, "format count");
    cursor += 2;
    for index in 0..formats {
        assert_eq!(i16_be(&payload, cursor), 1, "param {index} must be binary");
        cursor += 2;
    }

    let count = i16_be(&payload, cursor);
    assert_eq!(count, values.len() as i16, "value count");
    cursor += 2;
    for value in values {
        let len = i32_be(&payload, cursor);
        cursor += 4;
        match value {
            Some(bytes) => {
                assert_eq!(len as usize, bytes.len(), "value length");
                assert_eq!(
                    &payload[cursor..cursor + len as usize],
                    *bytes,
                    "value bytes"
                );
                cursor += len as usize;
            }
            None => {
                assert_eq!(len, -1, "NULL must use length -1");
            }
        }
    }

    // Result formats: one entry, text (0).
    assert_eq!(i16_be(&payload, cursor), 1, "result format count");
    assert_eq!(i16_be(&payload, cursor + 2), 0, "results must be text");
}

async fn assert_describe_portal<S: AsyncRead + std::marker::Unpin>(stream: &mut S) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'D', "expected Describe");
    assert_eq!(payload, vec![b'P', 0], "describe the unnamed portal");
}

async fn assert_execute_unlimited<S: AsyncRead + std::marker::Unpin>(stream: &mut S) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'E', "expected Execute");
    let (portal, next) = cstring(&payload, 0);
    assert_eq!(portal, "", "unnamed portal");
    assert_eq!(i32_be(&payload, next), 0, "max_rows must be 0");
}

async fn assert_sync<S: AsyncRead + std::marker::Unpin>(stream: &mut S) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'S', "expected Sync");
    assert!(payload.is_empty(), "Sync has no payload");
}

fn parameter_description(oids: &[i32]) -> Vec<u8> {
    let mut payload = (oids.len() as i16).to_be_bytes().to_vec();
    for oid in oids {
        payload.extend_from_slice(&oid.to_be_bytes());
    }
    payload
}

fn row_description(names: &[&str]) -> Vec<u8> {
    let mut payload = (names.len() as i16).to_be_bytes().to_vec();
    for name in names {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        // name + \0 + (table oid 4, attr 2, type oid 4, size 2, modifier 4, format 2).
        payload.extend_from_slice(&[0u8; 18]);
    }
    payload
}

fn data_row(values: &[Option<&str>]) -> Vec<u8> {
    let mut payload = (values.len() as i16).to_be_bytes().to_vec();
    for value in values {
        match value {
            Some(text) => {
                payload.extend_from_slice(&(text.len() as i32).to_be_bytes());
                payload.extend_from_slice(text.as_bytes());
            }
            None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    payload
}

/// Trust-flow startup over plain TCP, then one extended cycle with five
/// parameters (int8 / text / NULL / bool / float8) and a two-row result.
async fn row_cycle_server(mut stream: TcpStream) {
    assert_eq!(
        read_startup(&mut stream).await,
        anydb_postgres::protocol::PROTOCOL_VERSION_3
    );
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    assert_parse(
        &mut stream,
        "SELECT $1, $2, $3, $4, $5",
        &[20, 25, 0, 16, 701],
    )
    .await;
    assert_bind(
        &mut stream,
        &[
            Some(&42i64.to_be_bytes()[..]),
            Some(b"hola".as_slice()),
            None,
            Some(&[1u8]),
            Some(&2.5f64.to_be_bytes()[..]),
        ],
    )
    .await;
    assert_describe_portal(&mut stream).await;
    assert_execute_unlimited(&mut stream).await;
    assert_sync(&mut stream).await;

    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b'2', &[]).await;
    send(
        &mut stream,
        b't',
        &parameter_description(&[20, 25, 0, 16, 701]),
    )
    .await;
    send(&mut stream, b'T', &row_description(&["a", "b"])).await;
    send(&mut stream, b'D', &data_row(&[Some("one"), None])).await;
    send(&mut stream, b'D', &data_row(&[Some("two"), Some("x")])).await;
    send(&mut stream, b'C', b"SELECT 2\0").await;
    ready_for_query(&mut stream).await;
}

/// One extended cycle for a non-row statement: NoData from Describe and an
/// UPDATE command tag.
async fn update_cycle_server(mut stream: TcpStream) {
    assert_eq!(
        read_startup(&mut stream).await,
        anydb_postgres::protocol::PROTOCOL_VERSION_3
    );
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    assert_parse(&mut stream, "UPDATE t SET v = $1 WHERE id = $2", &[20, 20]).await;
    assert_bind(
        &mut stream,
        &[Some(&7i64.to_be_bytes()[..]), Some(&1i64.to_be_bytes()[..])],
    )
    .await;
    assert_describe_portal(&mut stream).await;
    assert_execute_unlimited(&mut stream).await;
    assert_sync(&mut stream).await;

    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b'2', &[]).await;
    send(&mut stream, b't', &parameter_description(&[20, 20])).await;
    send(&mut stream, b'n', &[]).await;
    send(&mut stream, b'C', b"UPDATE 3\0").await;
    ready_for_query(&mut stream).await;
}

/// One failing cycle (server-side SQLSTATE + message) followed by a ping:
/// the client must surface ExecutionFailed (with the code) AND keep the
/// connection usable.
async fn error_then_ping_server(
    mut stream: TcpStream,
    sqlstate: &'static str,
    message: &'static str,
) {
    assert_eq!(
        read_startup(&mut stream).await,
        anydb_postgres::protocol::PROTOCOL_VERSION_3
    );
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    for _ in 0..5 {
        let _ = read_message(&mut stream).await;
    }
    let mut error = Vec::new();
    for (code, value) in [('S', "ERROR"), ('C', sqlstate), ('M', message)] {
        error.extend_from_slice(format!("{code}{value}").as_bytes());
        error.push(0);
    }
    send(&mut stream, b'E', &error).await;
    // The aborted implicit transaction rolls back at Sync: the status byte
    // after the failing cycle is 'E' (_in a failed transaction_).
    ready_for_query_aborted(&mut stream).await;

    // Connection reuse: the ping (empty simple query) must still work.
    let (tag, payload) = read_message(&mut stream).await;
    assert_eq!(tag, b'Q', "ping after the failed cycle");
    assert_eq!(payload, vec![0], "ping is the empty query");
    send(&mut stream, b'I', &[]).await;
    ready_for_query(&mut stream).await;
}

/// Transaction flow: BEGIN (implicit txn becomes 'T'), a failing statement
/// ('T' -> 'E' with SQLSTATE 25P02), ROLLBACK (normalizes back to idle).
async fn transaction_flow_server(mut stream: TcpStream) {
    assert_eq!(
        read_startup(&mut stream).await,
        anydb_postgres::protocol::PROTOCOL_VERSION_3
    );
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    // Cycle 1: BEGIN -> CommandComplete "BEGIN", Ready 'T'.
    assert_parse(&mut stream, "BEGIN", &[]).await;
    assert_bind(&mut stream, &[]).await;
    assert_describe_portal(&mut stream).await;
    assert_execute_unlimited(&mut stream).await;
    assert_sync(&mut stream).await;
    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b'2', &[]).await;
    send(&mut stream, b't', &parameter_description(&[])).await;
    send(&mut stream, b'n', &[]).await;
    send(&mut stream, b'C', b"BEGIN\0").await;
    ready_for_query_in_txn(&mut stream).await;

    // Cycle 2: a statement that fails inside the transaction (25P02).
    for _ in 0..5 {
        let _ = read_message(&mut stream).await;
    }
    let mut error = Vec::new();
    for (code, value) in [
        ('S', "ERROR"),
        ('C', "25P02"),
        ('M', "current transaction is aborted"),
    ] {
        error.extend_from_slice(format!("{code}{value}").as_bytes());
        error.push(0);
    }
    send(&mut stream, b'E', &error).await;
    ready_for_query_aborted(&mut stream).await;

    // Cycle 3: ROLLBACK back to idle.
    assert_parse(&mut stream, "ROLLBACK", &[]).await;
    assert_bind(&mut stream, &[]).await;
    assert_describe_portal(&mut stream).await;
    assert_execute_unlimited(&mut stream).await;
    assert_sync(&mut stream).await;
    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b'2', &[]).await;
    send(&mut stream, b't', &parameter_description(&[])).await;
    send(&mut stream, b'n', &[]).await;
    send(&mut stream, b'C', b"ROLLBACK\0").await;
    ready_for_query(&mut stream).await;
}

/// Driver-level SPI cycle: int8 parameter through execute_statement.
async fn spi_cycle_server(mut stream: TcpStream) {
    assert_eq!(
        read_startup(&mut stream).await,
        anydb_postgres::protocol::PROTOCOL_VERSION_3
    );
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    assert_parse(&mut stream, "SELECT $1 AS n", &[20]).await;
    assert_bind(&mut stream, &[Some(&3i64.to_be_bytes()[..])]).await;
    assert_describe_portal(&mut stream).await;
    assert_execute_unlimited(&mut stream).await;
    assert_sync(&mut stream).await;

    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b'2', &[]).await;
    send(&mut stream, b't', &parameter_description(&[20])).await;
    send(&mut stream, b'T', &row_description(&["n"])).await;
    send(&mut stream, b'D', &data_row(&[Some("3")])).await;
    send(&mut stream, b'C', b"SELECT 1\0").await;
    ready_for_query(&mut stream).await;

    let (tag, _) = read_message(&mut stream).await;
    assert_eq!(tag, b'X', "close must send Terminate");
}

// ---------- tests ----------

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

#[tokio::test]
async fn extended_query_encodes_parameters_and_returns_rows() {
    let (address, server) = spawn_backend(row_cycle_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");
    let result = connection
        .extended_query(
            "SELECT $1, $2, $3, $4, $5",
            &[
                QueryParameter::Integer(42),
                QueryParameter::Text("hola".to_owned()),
                QueryParameter::Null,
                QueryParameter::Boolean(true),
                QueryParameter::Float(2.5),
            ],
        )
        .await
        .expect("extended query");
    assert_eq!(result.columns, vec!["a", "b"]);
    assert_eq!(
        result.rows,
        vec![
            vec![Some("one".to_owned()), None],
            vec![Some("two".to_owned()), Some("x".to_owned())],
        ]
    );
    assert_eq!(result.command_tag.as_deref(), Some("SELECT 2"));
    assert_eq!(result.affected_rows, Some(2));
    server.await.expect("server task");
}

#[tokio::test]
async fn extended_query_reports_affected_rows_for_updates() {
    let (address, server) = spawn_backend(update_cycle_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");
    let result = connection
        .extended_query(
            "UPDATE t SET v = $1 WHERE id = $2",
            &[QueryParameter::Integer(7), QueryParameter::Integer(1)],
        )
        .await
        .expect("extended update");
    assert!(result.columns.is_empty(), "NoData for non-row statements");
    assert!(result.rows.is_empty());
    assert_eq!(result.command_tag.as_deref(), Some("UPDATE 3"));
    assert_eq!(result.affected_rows, Some(3));
    server.await.expect("server task");
}

#[tokio::test]
async fn runtime_errors_map_to_execution_failed_and_connection_stays_reusable() {
    let (address, server) = spawn_backend(|stream| {
        error_then_ping_server(stream, "42P10", "relation \"missing\" does not exist")
    })
    .await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");
    let error = connection
        .extended_query("SELECT * FROM missing", &[])
        .await
        .expect_err("must fail");
    // SQLSTATE rides along for classification (42P10 from the backend).
    assert_eq!(
        error,
        ConnectionError::ExecutionFailed {
            sqlstate: Some("42P10".to_owned()),
            message: "relation \"missing\" does not exist".to_owned(),
        }
    );
    // Pipeline classification: syntax-class codes must NOT trigger recovery.
    assert_eq!(sqlstate_type(&error), anydb_shared::ErrorType::Normal);
    // The failed cycle completed its drain up to ReadyForQuery: the next
    // statement on the same connection works.
    connection.simple_query("").await.expect("ping after error");
    server.await.expect("server task");
}

#[tokio::test]
async fn aborted_transaction_sqlstate_classifies_for_recovery() {
    let (address, server) = spawn_backend(|stream| {
        error_then_ping_server(
            stream,
            "25P02",
            "current transaction is aborted, commands ignored until end of transaction block",
        )
    })
    .await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");
    let error = connection
        .extended_query("SELECT 1", &[])
        .await
        .expect_err("must fail");
    assert_eq!(
        sqlstate_type(&error),
        anydb_shared::ErrorType::TransactionAborted
    );
    connection.simple_query("").await.expect("ping after abort");
    server.await.expect("server task");
}

/// Driver-supplied classifier plumbing (the recovery loop consumes this).
fn sqlstate_type(error: &ConnectionError) -> anydb_shared::ErrorType {
    use anydb_postgres::classification::SqlStateClassifier;
    use anydb_shared::driver::classification::ErrorClassifier;
    SqlStateClassifier.classify(error)
}

#[tokio::test]
async fn explicit_transaction_flow_tracks_status_transitions() {
    let (address, server) = spawn_backend(transaction_flow_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");
    assert_eq!(
        connection.transaction_status(),
        anydb_postgres::protocol::TxnStatus::Idle
    );

    connection.begin().await.expect("BEGIN");
    assert_eq!(
        connection.transaction_status(),
        anydb_postgres::protocol::TxnStatus::InTransaction
    );

    let error = connection
        .extended_query("SELECT 1", &[])
        .await
        .expect_err("must fail with 25P02");
    match error {
        ConnectionError::ExecutionFailed { sqlstate, .. } => {
            assert_eq!(sqlstate.as_deref(), Some("25P02"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        connection.transaction_status(),
        anydb_postgres::protocol::TxnStatus::Failed
    );

    connection.rollback().await.expect("ROLLBACK");
    assert_eq!(
        connection.transaction_status(),
        anydb_postgres::protocol::TxnStatus::Idle
    );
    server.await.expect("server task");
}

#[tokio::test]
async fn execute_statement_goes_through_the_spi() {
    let (address, server) = spawn_backend(spi_cycle_server).await;
    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "c1".into(),
        target: format!("postgres://user@{}/db", address),
        properties: Default::default(),
    };
    let source = driver.open_data_source(request).await.expect("open");
    let result = source
        .execute_statement("SELECT $1 AS n", &[QueryParameter::Integer(3)])
        .await
        .expect("execute");
    assert_eq!(result.columns, vec!["n"]);
    assert_eq!(result.rows, vec![vec![Some("3".to_owned())]]);
    assert_eq!(result.command_tag.as_deref(), Some("SELECT 1"));
    assert_eq!(result.affected_rows, Some(1));
    source.close().await;
    server.await.expect("server task");
}

/// SPI transaction control: `BEGIN` (Ready `T`) then `COMMIT` (Ready `I`)
/// over the `DataSource` trait methods (DBeaver session txn control).
async fn spi_transaction_cycle_server(mut stream: TcpStream) {
    assert_eq!(
        read_startup(&mut stream).await,
        anydb_postgres::protocol::PROTOCOL_VERSION_3
    );
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    for (control, tag) in [("BEGIN", b"T".as_slice()), ("COMMIT", b"I")] {
        assert_parse(&mut stream, control, &[]).await;
        assert_bind(&mut stream, &[]).await;
        assert_describe_portal(&mut stream).await;
        assert_execute_unlimited(&mut stream).await;
        assert_sync(&mut stream).await;
        send(&mut stream, b'1', &[]).await;
        send(&mut stream, b'2', &[]).await;
        send(&mut stream, b't', &parameter_description(&[])).await;
        send(&mut stream, b'n', &[]).await;
        send(&mut stream, b'C', format!("{control}\0").as_bytes()).await;
        if tag == b"T" {
            ready_for_query_in_txn(&mut stream).await;
        } else {
            ready_for_query(&mut stream).await;
        }
    }

    let (terminate, _) = read_message(&mut stream).await;
    assert_eq!(terminate, b'X', "close must send Terminate");
}

#[tokio::test]
async fn spi_exposes_begin_and_commit_transaction_control() {
    let (address, server) = spawn_backend(spi_transaction_cycle_server).await;
    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "c1".into(),
        target: format!("postgres://user@{}/db", address),
        properties: Default::default(),
    };
    let source = driver.open_data_source(request).await.expect("open");

    source.begin_transaction().await.expect("BEGIN over SPI");
    source.commit_transaction().await.expect("COMMIT over SPI");

    source.close().await;
    server.await.expect("server task");
}
