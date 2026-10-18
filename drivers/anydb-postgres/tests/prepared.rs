//! Named prepared statement reuse: the backend verifies the prepare cycle
//! (Parse(name) -> Describe statement(name) -> Sync), then two Bind/Execute/
//! Sync runs of the same statement without any re-parse, plus the ghost
//! statement error path staying reusably drained.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use anydb_postgres::protocol::{ColumnMeta, Connection as WireConnection, Prepared};
use anydb_postgres::types;
use anydb_shared::ConnectionError;
use anydb_shared::driver::statement::{QueryParameter, TypedValue};

// ---------- transport helpers (same pattern as extended.rs) ----------

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

/// Asserts a named Parse shape and returns the parsed SQL.
async fn assert_parse_named<S: AsyncRead + std::marker::Unpin>(
    stream: &mut S,
    name: &str,
    sql: &str,
    oids: &[i32],
) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'P', "expected Parse");
    let (parsed_name, next) = cstring(&payload, 0);
    assert_eq!(parsed_name, name, "unexpected statement name");
    let (parsed_sql, next) = cstring(&payload, next);
    assert_eq!(parsed_sql, sql, "unexpected SQL");
    assert_eq!(i16_be(&payload, next), oids.len() as i16, "param count");
    for (index, oid) in oids.iter().enumerate() {
        let offset = next + 2 + index * 4;
        assert_eq!(i32_be(&payload, offset), *oid, "param {index} OID");
    }
}

/// Asserts the Describe of a named statement.
async fn assert_describe_statement<S: AsyncRead + std::marker::Unpin>(stream: &mut S, name: &str) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'D', "expected Describe");
    assert_eq!(
        payload,
        {
            let mut expected = name.as_bytes().to_vec();
            expected.push(0);
            expected
        },
        "describe the named statement"
    );
}

/// Asserts the Bind of a prepared run: unnamed portal bind to the named
/// statement, binary params and the requested result formats.
async fn assert_prepared_run_bind<S: AsyncRead + std::marker::Unpin>(
    stream: &mut S,
    statement: &str,
    values: &[Option<&[u8]>],
    result_formats: &[i16],
) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'B', "expected Bind");
    let (portal, next) = cstring(&payload, 0);
    assert_eq!(portal, "", "unnamed portal");
    let (parsed_statement, mut cursor) = cstring(&payload, next);
    assert_eq!(parsed_statement, statement, "unexpected statement");

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

    assert_eq!(
        i16_be(&payload, cursor),
        result_formats.len() as i16,
        "result format count"
    );
    for (index, format) in result_formats.iter().enumerate() {
        assert_eq!(
            i16_be(&payload, cursor + 2 + index * 2),
            *format,
            "result column {index} format"
        );
    }
}

async fn assert_execute_unlimited<S: AsyncRead + std::marker::Unpin>(stream: &mut S) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'E', "expected Execute");
    let (portal, next) = cstring(&payload, 0);
    assert_eq!(portal, "", "unnamed portal");
    assert_eq!(i32_be(&payload, next), 0, "max_rows must be 0");
}

fn row_description_typed(columns: &[(&str, i32)]) -> Vec<u8> {
    let mut payload = (columns.len() as i16).to_be_bytes().to_vec();
    for (name, oid) in columns {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        // name + \0 + (table oid 4, attr 2, type oid 4, size 2, modifier 4, format 2).
        payload.extend_from_slice(&[0u8; 6]);
        payload.extend_from_slice(&oid.to_be_bytes());
        payload.extend_from_slice(&[0u8; 8]);
    }
    payload
}

fn typed_data_row(values: &[Option<&[u8]>]) -> Vec<u8> {
    let mut payload = (values.len() as i16).to_be_bytes().to_vec();
    for value in values {
        match value {
            Some(bytes) => {
                payload.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                payload.extend_from_slice(bytes);
            }
            None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    payload
}

fn parameter_description(oids: &[i32]) -> Vec<u8> {
    let mut payload = (oids.len() as i16).to_be_bytes().to_vec();
    for oid in oids {
        payload.extend_from_slice(&oid.to_be_bytes());
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

// ---------- prepared reuse flows ----------

/// Prepare once ("SELECT $1 + 1", param type inferred server-side), run
/// twice with different parameters: no re-parse between runs.
async fn prepared_reuse_server(mut stream: TcpStream) {
    let len = stream.read_u32().await.expect("startup length");
    let mut startup = vec![0u8; len as usize - 4];
    stream.read_exact(&mut startup).await.expect("startup body");
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    // Prepare cycle: named parse, named describe, sync.
    assert_parse_named(&mut stream, "q1", "SELECT $1 + 1", &[]).await;
    assert_describe_statement(&mut stream, "q1").await;
    assert!(expect_tag(&mut stream, b'S').await.is_empty());
    send(&mut stream, b'1', &[]).await;
    send(
        &mut stream,
        b't',
        &parameter_description(&[types::oid::INT8]),
    )
    .await;
    send(
        &mut stream,
        b'T',
        &row_description_typed(&[("sum", types::oid::INT8)]),
    )
    .await;
    ready_for_query(&mut stream).await;

    // Two reuse runs: Bind references the statement name only.
    for input in [10i64, 20] {
        assert_prepared_run_bind(&mut stream, "q1", &[Some(&input.to_be_bytes())], &[1]).await;
        assert_execute_unlimited(&mut stream).await;
        assert!(expect_tag(&mut stream, b'S').await.is_empty());
        send(&mut stream, b'2', &[]).await;
        let output = input + 1;
        send(
            &mut stream,
            b'D',
            &typed_data_row(&[Some(&output.to_be_bytes())]),
        )
        .await;
        send(&mut stream, b'C', b"SELECT 1\0").await;
        ready_for_query(&mut stream).await;
    }
}

#[tokio::test]
async fn prepared_statement_runs_without_reparse() {
    let (address, server) = spawn_backend(prepared_reuse_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");

    let prepared = connection
        .prepare("q1", "SELECT $1 + 1")
        .await
        .expect("prepare");
    // The server inferred int8 for the parameter: client sent no OIDs.
    assert_eq!(prepared.param_oids, vec![types::oid::INT8]);
    assert_eq!(
        prepared.columns,
        vec![ColumnMeta {
            name: "sum".into(),
            oid: types::oid::INT8
        }]
    );
    // int8 is cataloged: binary result format decided at prepare time.
    assert_eq!(prepared.result_formats, vec![1]);

    for input in [10i64, 20] {
        let result = connection
            .run_prepared(&prepared, &[QueryParameter::Integer(input)])
            .await
            .expect("run prepared");
        let expected = input + 1;
        assert_eq!(result.rows, vec![vec![Some(TypedValue::Int8(expected))]],);
        assert_eq!(result.command_tag.as_deref(), Some("SELECT 1"));
        assert_eq!(result.affected_rows, Some(1));
    }

    connection.terminate().await;
    server.await.expect("server task");
}

/// A Bind against a never-prepared statement name errors with SQLSTATE
/// 26000 and the connection stays usable: drained until Z both times.
async fn ghost_statement_server(mut stream: TcpStream) {
    let len = stream.read_u32().await.expect("startup length");
    let mut startup = vec![0u8; len as usize - 4];
    stream.read_exact(&mut startup).await.expect("startup body");
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    for _ in 0..2 {
        let (tag, _) = read_message(&mut stream).await;
        assert_eq!(tag, b'B', "expected Bind");
        for _ in 0..2 {
            read_message(&mut stream).await;
        }
        let mut error = Vec::new();
        for (code, value) in [
            ('S', "ERROR"),
            ('C', "26000"),
            ('M', "prepared statement does not exist"),
        ] {
            error.extend_from_slice(format!("{code}{value}").as_bytes());
            error.push(0);
        }
        send(&mut stream, b'E', &error).await;
        send(&mut stream, b'Z', b"I").await;
    }
}

#[tokio::test]
async fn ghost_prepared_statement_errors_and_stays_reusable() {
    let (address, server) = spawn_backend(ghost_statement_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");

    let ghost = Prepared {
        name: "q2".into(),
        sql: "SELECT 1".into(),
        param_oids: vec![types::oid::INT8],
        columns: vec![ColumnMeta {
            name: "n".into(),
            oid: types::oid::INT8,
        }],
        result_formats: vec![1],
    };

    for _ in 0..2 {
        let error = connection
            .run_prepared(&ghost, &[QueryParameter::Integer(1)])
            .await
            .expect_err("ghost statement must fail");
        match error {
            ConnectionError::ExecutionFailed { sqlstate, .. } => {
                assert_eq!(sqlstate.as_deref(), Some("26000"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    connection.terminate().await;
    server.await.expect("server task");
}
