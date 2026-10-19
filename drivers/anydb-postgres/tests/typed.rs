//! Typed query integration: the backend verifies the full describe-first
//! wire sequence (Parse -> Describe statement -> Flush, then
//! Bind -> Execute -> Sync), the per-column result formats chosen from the
//! type catalog (binary for cataloged OIDs, text for the rest) and the
//! typed value decoding, NULLs included.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use anydb_postgres::PostgresDriver;
use anydb_postgres::protocol::{ColumnMeta, Connection as WireConnection};
use anydb_postgres::types;
use anydb_shared::driver::spi::{Driver, OpenRequest};
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

/// Reads one message and asserts only its tag.
async fn expect_tag<S: AsyncRead + std::marker::Unpin>(stream: &mut S, tag: u8) -> Vec<u8> {
    let (next, payload) = read_message(stream).await;
    assert_eq!(next, tag, "unexpected message");
    payload
}

/// Asserts the Execute message: unnamed portal, all rows (max_rows = 0).
async fn assert_execute_unlimited<S: AsyncRead + std::marker::Unpin>(stream: &mut S) {
    let (tag, payload) = read_message(stream).await;
    assert_eq!(tag, b'E', "expected Execute");
    let (portal, next) = cstring(&payload, 0);
    assert_eq!(portal, "", "unnamed portal");
    assert_eq!(i32_be(&payload, next), 0, "max_rows must be 0");
}

/// Asserts the Parse message shape (unnamed statement + declared OIDs).
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

/// Asserts the Bind of a typed flow: binary params, per-column result
/// formats and the exact value bytes.
async fn assert_typed_bind<S: AsyncRead + std::marker::Unpin>(
    stream: &mut S,
    values: &[Option<&[u8]>],
    result_formats: &[i16],
) {
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

/// RowDescription with real type OIDs (18 fixed bytes per column).
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

/// DataRow with raw per-column bytes (`None` = NULL, length -1).
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

/// Builds a numeric binary payload (ndigits, weight, sign, dscale as
/// int16's, then the base-10000 digit groups) — the layout verified
/// against the live postgres in the numeric smoke.
fn numeric_be(weight: i16, dscale: u16, groups: &[u16]) -> Vec<u8> {
    let mut bytes = (groups.len() as u16).to_be_bytes().to_vec();
    bytes.extend_from_slice(&weight.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes()); // sign: positive
    bytes.extend_from_slice(&dscale.to_be_bytes());
    for group in groups {
        bytes.extend_from_slice(&group.to_be_bytes());
    }
    bytes
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

// ---------- typed-query flows ----------

async fn typed_row_cycle_server(mut stream: TcpStream) {
    // Startup handshake.
    let len = stream.read_u32().await.expect("startup length");
    let mut startup = vec![0u8; len as usize - 4];
    stream.read_exact(&mut startup).await.expect("startup body");
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    // Describe phase: Parse, Describe statement, Flush.
    assert_parse(
        &mut stream,
        "SELECT $1, $2, $3, $4",
        &[
            types::oid::INT8,
            types::oid::FLOAT8,
            types::oid::BOOL,
            types::oid::TEXT,
        ],
    )
    .await;
    assert_eq!(expect_tag(&mut stream, b'D').await, vec![b'S', 0]);
    assert!(expect_tag(&mut stream, b'H').await.is_empty());

    // Metadata answers until the RowDescription: the client must not send
    // Bind before it knows the column OIDs.
    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b't', &{
        let oids = [
            types::oid::INT8,
            types::oid::FLOAT8,
            types::oid::BOOL,
            types::oid::TEXT,
        ];
        let mut payload = (oids.len() as i16).to_be_bytes().to_vec();
        for oid in oids {
            payload.extend_from_slice(&oid.to_be_bytes());
        }
        payload
    })
    .await;
    send(
        &mut stream,
        b'T',
        &row_description_typed(&[
            ("n", types::oid::INT8),
            ("f", types::oid::FLOAT8),
            ("b", types::oid::BOOL),
            ("x", types::oid::TEXT),
            ("num", 1700), // numeric: binary since the catalog covers it
        ]),
    )
    .await;

    // Execution phase: Bind (binary params + catalog formats), Execute, Sync.
    let float_be = 3.5f64.to_be_bytes();
    let float_be_2 = 2.5f64.to_be_bytes();
    assert_typed_bind(
        &mut stream,
        &[
            Some(&42i64.to_be_bytes()),
            Some(&float_be),
            Some(&[1]),
            Some(b"hola"),
        ],
        &[1, 1, 1, 1, 1],
    )
    .await;
    assert_execute_unlimited(&mut stream).await;
    assert!(expect_tag(&mut stream, b'S').await.is_empty());

    send(&mut stream, b'2', &[]).await;
    send(
        &mut stream,
        b'D',
        &typed_data_row(&[
            Some(&42i64.to_be_bytes()),
            Some(&float_be),
            Some(&[1]),
            Some(b"hola"),
            Some(&numeric_be(0, 2, &[1, 2300])), // 1.23
        ]),
    )
    .await;
    send(
        &mut stream,
        b'D',
        &typed_data_row(&[
            None,
            Some(&float_be_2),
            Some(&[0]),
            None,
            Some(&numeric_be(0, 2, &[7, 8000])), // 7.80
        ]),
    )
    .await;
    send(&mut stream, b'C', b"SELECT 2\0").await;
    ready_for_query(&mut stream).await;
}

#[tokio::test]
async fn execute_statement_typed_goes_through_the_spi() {
    let (address, server) = spawn_backend(typed_row_cycle_server).await;
    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "c1".into(),
        target: format!("postgres://user@{}/db", address),
        properties: Default::default(),
    };
    let source = driver.open_data_source(request).await.expect("open");

    let result = source
        .execute_statement_typed(
            "SELECT $1, $2, $3, $4",
            &[
                QueryParameter::Integer(42),
                QueryParameter::Float(3.5),
                QueryParameter::Boolean(true),
                QueryParameter::Text("hola".to_owned()),
            ],
        )
        .await
        .expect("typed SPI execute");

    assert_eq!(result.columns, vec!["n", "f", "b", "x", "num"]);
    assert_eq!(
        result.rows,
        vec![
            vec![
                Some(TypedValue::Int8(42)),
                Some(TypedValue::Float8(3.5)),
                Some(TypedValue::Boolean(true)),
                Some(TypedValue::Text("hola".into())),
                Some(TypedValue::BigDecimal("1.23".into())),
            ],
            vec![
                None,
                Some(TypedValue::Float8(2.5)),
                Some(TypedValue::Boolean(false)),
                None,
                Some(TypedValue::BigDecimal("7.80".into())),
            ],
        ]
    );
    assert_eq!(result.command_tag.as_deref(), Some("SELECT 2"));

    source.close().await;
    server.await.expect("server task");
}

#[tokio::test]
async fn typed_query_decodes_cataloged_columns_and_nulls() {
    let (address, server) = spawn_backend(typed_row_cycle_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");

    let result = connection
        .typed_query(
            "SELECT $1, $2, $3, $4",
            &[
                QueryParameter::Integer(42),
                QueryParameter::Float(3.5),
                QueryParameter::Boolean(true),
                QueryParameter::Text("hola".to_owned()),
            ],
        )
        .await
        .expect("typed query");

    assert_eq!(
        result.columns,
        vec![
            ColumnMeta {
                name: "n".into(),
                oid: types::oid::INT8
            },
            ColumnMeta {
                name: "f".into(),
                oid: types::oid::FLOAT8
            },
            ColumnMeta {
                name: "b".into(),
                oid: types::oid::BOOL
            },
            ColumnMeta {
                name: "x".into(),
                oid: types::oid::TEXT
            },
            ColumnMeta {
                name: "num".into(),
                oid: 1700
            },
        ]
    );
    assert_eq!(
        result.rows,
        vec![
            vec![
                Some(TypedValue::Int8(42)),
                Some(TypedValue::Float8(3.5)),
                Some(TypedValue::Boolean(true)),
                Some(TypedValue::Text("hola".into())),
                Some(TypedValue::BigDecimal("1.23".into())),
            ],
            vec![
                None,
                Some(TypedValue::Float8(2.5)),
                Some(TypedValue::Boolean(false)),
                None,
                Some(TypedValue::BigDecimal("7.80".into())),
            ],
        ]
    );
    assert_eq!(result.command_tag.as_deref(), Some("SELECT 2"));
    assert_eq!(result.affected_rows, Some(2));

    connection.terminate().await;
    server.await.expect("server task");
}

/// Statements without result columns: `NoData` ends the describe phase and
/// the Bind carries an empty result-format list.
async fn typed_command_cycle_server(mut stream: TcpStream) {
    let len = stream.read_u32().await.expect("startup length");
    let mut startup = vec![0u8; len as usize - 4];
    stream.read_exact(&mut startup).await.expect("startup body");
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;

    assert_parse(&mut stream, "UPDATE t SET v = $1", &[types::oid::INT8]).await;
    assert_eq!(expect_tag(&mut stream, b'D').await, vec![b'S', 0]);
    assert!(expect_tag(&mut stream, b'H').await.is_empty());
    send(&mut stream, b'1', &[]).await;
    send(&mut stream, b't', &{
        let mut payload = 1i16.to_be_bytes().to_vec();
        payload.extend_from_slice(&types::oid::INT8.to_be_bytes());
        payload
    })
    .await;
    send(&mut stream, b'n', &[]).await;

    assert_typed_bind(&mut stream, &[Some(&3i64.to_be_bytes())], &[]).await;
    assert_execute_unlimited(&mut stream).await;
    assert!(expect_tag(&mut stream, b'S').await.is_empty());

    send(&mut stream, b'2', &[]).await;
    send(&mut stream, b'C', b"UPDATE 5\0").await;
    ready_for_query(&mut stream).await;
}

#[tokio::test]
async fn typed_query_without_result_columns_skips_formats() {
    let (address, server) = spawn_backend(typed_command_cycle_server).await;
    let mut connection = WireConnection::connect(&target(address))
        .await
        .expect("connect");

    let result = connection
        .typed_query("UPDATE t SET v = $1", &[QueryParameter::Integer(3)])
        .await
        .expect("typed command");

    assert!(result.columns.is_empty(), "NoData must leave no columns");
    assert!(result.rows.is_empty());
    assert_eq!(result.command_tag.as_deref(), Some("UPDATE 5"));
    assert_eq!(result.affected_rows, Some(5));

    connection.terminate().await;
    server.await.expect("server task");
}
