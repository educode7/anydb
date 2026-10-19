//! Cursor-id batch paging: `find` with `batchSize` suspends while the
//! reply's `cursor.id` is non-zero, `getMore` fetches the next batch
//! and the drained reply (id 0) completes the flow; an abandoned
//! suspended cursor is `killCursors`-ed best-effort before a new flow.
//! Mirrors the postgres portal-paging test shape with mongo semantics.

use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use anydb_mongo::WireDataSource;
use anydb_mongo::bson::{Bson, Document};
use anydb_mongo::uri::parse_target;
use anydb_shared::ConnectionError;
use anydb_shared::driver::spi::DataSource as _;
use anydb_shared::driver::statement::TypedValue;

// ---------- wire helpers on the fake server ----------

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(i32, Document)> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await.ok()?;
    let length = i32::from_le_bytes(header[0..4].try_into().expect("4 bytes"));
    let request_id = i32::from_le_bytes(header[4..8].try_into().expect("4 bytes"));
    let mut body = vec![0u8; (length - 16) as usize];
    stream.read_exact(&mut body).await.ok()?;
    Some((
        request_id,
        anydb_mongo::bson::parse_document(&body[4..]).ok()?,
    ))
}

async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, response_to: i32, body: &Document) {
    let document = anydb_mongo::bson::encode_document(body).expect("reply encodes");
    let length = (20 + document.len()) as i32;
    let mut out = Vec::with_capacity(length as usize);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&2i32.to_le_bytes());
    out.extend_from_slice(&response_to.to_le_bytes());
    out.extend_from_slice(&2013i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&document);
    stream.write_all(&out).await.expect("reply write");
    stream.flush().await.expect("reply flush");
}

fn int32(value: i32) -> Bson {
    Bson::Int32(value)
}

fn int64(value: i64) -> Bson {
    Bson::Int64(value)
}

fn double_ok() -> Bson {
    Bson::Double(1.0)
}

fn doc_n(value: i32) -> Document {
    Document::from(vec![("n".to_owned(), int32(value))])
}

fn cursor_doc(id: Bson, batch_name: &str, batch: Vec<Document>) -> Document {
    Document::from(vec![
        ("id".to_owned(), id),
        ("ns".to_owned(), Bson::String("authdb.c1".to_owned())),
        (
            batch_name.to_owned(),
            Bson::Array(batch.into_iter().map(Bson::Document).collect()),
        ),
    ])
}

fn first_command(document: &Document) -> &str {
    document
        .first()
        .map(|(key, _)| key.as_str())
        .expect("command has a first field")
}

fn find_field<'a>(command: &'a Document, key: &str) -> &'a Bson {
    command
        .iter()
        .find(|(field, _)| field == key)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("find command carries {key}"))
}

/// The hello handshake preamble every scripted server starts with.
async fn handshake<S: AsyncRead + Unpin + AsyncWrite + Unpin>(stream: &mut S) {
    let Some((request_id, command)) = read_frame(stream).await else {
        panic!("handshake read");
    };
    assert_eq!(first_command(&command), "hello");
    write_frame(
        stream,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), double_ok()),
            (
                "version".to_owned(),
                Bson::String("8.0.0-fake-page".to_owned()),
            ),
        ]),
    )
    .await;
}

/// One threaded server; the handler owns the whole conversation.
fn spawn_server<F, Fut>(handler: F) -> (u16, tokio::task::JoinHandle<()>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let handle = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        handler(stream).await;
    });
    (port, handle)
}

fn connection_for(port: u16) -> impl Future<Output = anydb_mongo::wire::Connection> {
    let target = parse_target(&format!("mongodb://127.0.0.1:{port}"), None).expect("target parses");
    async move {
        anydb_mongo::wire::Connection::connect(&target)
            .await
            .expect("connect")
    }
}

fn source_for(port: u16) -> impl Future<Output = Arc<WireDataSource>> {
    let target = parse_target(&format!("mongodb://127.0.0.1:{port}"), None).expect("target parses");
    async move { WireDataSource::open(&target).await.expect("open") }
}

// ---------- server scripts ----------

/// Six rows in three batches of two: find(2) + two getMore rounds, the
/// last one draining the cursor id to 0. Logs every scripted step.
async fn six_batches_server(stream: TcpStream, log: Arc<StdMutex<Vec<String>>>) {
    let mut stream = stream;
    handshake(&mut stream).await;

    // Startup: find with batchSize 2 (the collection is the find value;
    // no separate 'collection' field exists on the find command).
    let Some((request_id, command)) = read_frame(&mut stream).await else {
        return;
    };
    assert_eq!(first_command(&command), "find");
    assert_eq!(find_field(&command, "find"), &Bson::String("c1".to_owned()));
    assert_eq!(find_field(&command, "batchSize"), &int32(2));
    assert!(
        !command.iter().any(|(field, _)| field == "singleBatch"),
        "the paged find must not force singleBatch"
    );
    log.lock().expect("log").push("find".to_owned());
    write_frame(
        &mut stream,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), int32(1)),
            (
                "cursor".to_owned(),
                Bson::Document(cursor_doc(
                    int64(42),
                    "firstBatch",
                    vec![doc_n(0), doc_n(1)],
                )),
            ),
        ]),
    )
    .await;

    // Two getMore rounds; the server keeps the SAME cursor id (mongo
    // semantics) until the final one drains it to 0.
    for round in 0..2 {
        let Some((request_id, command)) = read_frame(&mut stream).await else {
            return;
        };
        assert_eq!(first_command(&command), "getMore");
        assert_eq!(find_field(&command, "getMore"), &int64(42));
        assert_eq!(
            find_field(&command, "collection"),
            &Bson::String("c1".to_owned())
        );
        log.lock().expect("log").push("getMore".to_owned());
        let drained = round == 1;
        let (id, batch) = if drained {
            (int64(0), vec![doc_n(4), doc_n(5)])
        } else {
            (int64(42), vec![doc_n(2), doc_n(3)])
        };
        write_frame(
            &mut stream,
            request_id,
            &Document::from(vec![
                ("ok".to_owned(), int32(1)),
                (
                    "cursor".to_owned(),
                    Bson::Document(cursor_doc(id, "nextBatch", batch)),
                ),
            ]),
        )
        .await;
    }
}

#[tokio::test]
async fn paged_cursor_streams_the_whole_answer_in_batches() {
    let log = Arc::new(StdMutex::new(Vec::new()));
    let (port, server) = {
        let log = log.clone();
        spawn_server(move |stream| six_batches_server(stream, log))
    };

    let mut connection = connection_for(port).await;
    let first = connection
        .find_page_start("c1", &Document::new(), 2)
        .await
        .expect("first batch");
    assert!(first.suspended);
    assert_eq!(
        first
            .documents
            .iter()
            .map(|document| document.first().map(|(_, value)| value.clone()))
            .collect::<Vec<_>>(),
        vec![Some(int32(0)), Some(int32(1))]
    );
    assert_eq!(first.total, 2);

    let second = connection.find_page_continue().await.expect("second batch");
    assert!(second.suspended);
    assert_eq!(second.total, 4);

    let last = connection.find_page_continue().await.expect("final batch");
    assert!(!last.suspended, "the drained reply completes the flow");
    assert_eq!(last.total, 6);

    // A completed flow releases the cursor: continuing now is an error.
    let error = connection
        .find_page_continue()
        .await
        .expect_err("no cursor");
    assert!(matches!(
        error,
        ConnectionError::Protocol(ref message) if message.contains("no suspended cursor")
    ));

    assert_eq!(
        *log.lock().expect("log"),
        vec!["find", "getMore", "getMore"]
    );
    connection.terminate().await;
    server.await.expect("server task");
}

#[tokio::test]
async fn driver_surface_types_the_batches() {
    let log = Arc::new(StdMutex::new(Vec::new()));
    let (port, server) = {
        let log = log.clone();
        spawn_server(move |stream| six_batches_server(stream, log))
    };
    let source = source_for(port).await;

    let first = source
        .query_page_start("find c1", &[], 2)
        .await
        .expect("first batch");
    assert!(first.suspended);
    assert_eq!(first.result.columns, vec!["n"]);
    assert_eq!(
        first.result.rows,
        vec![
            vec![Some(TypedValue::Int4(0))],
            vec![Some(TypedValue::Int4(1))],
        ]
    );
    // Suspended batches carry no command tag (postgres parity).
    assert_eq!(first.result.command_tag, None);
    assert_eq!(first.result.affected_rows, None);

    source.query_page_continue().await.expect("second batch");
    let last = source.query_page_continue().await.expect("final batch");
    assert!(!last.suspended);
    assert_eq!(last.result.command_tag.as_deref(), Some("find 6"));
    assert_eq!(last.result.affected_rows, Some(6));

    source.close().await;
    server.await.expect("server task");
}

/// A suspended page is abandoned by a new `query_page_start`: the
/// server must observe killCursors with the suspended id before the
/// fresh find, and the reply never claims a cursor back.
async fn abandon_server(stream: TcpStream) {
    let mut stream = stream;
    handshake(&mut stream).await;

    // First flow: one document with a live cursor id.
    let Some((request_id, command)) = read_frame(&mut stream).await else {
        return;
    };
    assert_eq!(first_command(&command), "find");
    write_frame(
        &mut stream,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), int32(1)),
            (
                "cursor".to_owned(),
                Bson::Document(cursor_doc(int64(77), "firstBatch", vec![doc_n(7)])),
            ),
        ]),
    )
    .await;

    // The abandoned flow is killed: killCursors with the suspended id.
    let Some((request_id, command)) = read_frame(&mut stream).await else {
        return;
    };
    assert_eq!(first_command(&command), "killCursors");
    assert_eq!(
        find_field(&command, "killCursors"),
        &Bson::String("c1".to_owned())
    );
    assert_eq!(
        find_field(&command, "cursors"),
        &Bson::Array(vec![int64(77)])
    );
    write_frame(
        &mut stream,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), int32(1)),
            ("cursorsKilled".to_owned(), Bson::Array(vec![int64(77)])),
            ("cursorsNotFound".to_owned(), Bson::Array(vec![])),
        ]),
    )
    .await;

    // The fresh flow completes on its first reply.
    let Some((request_id, _command)) = read_frame(&mut stream).await else {
        return;
    };
    write_frame(
        &mut stream,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), int32(1)),
            (
                "cursor".to_owned(),
                Bson::Document(cursor_doc(int64(0), "firstBatch", vec![doc_n(8)])),
            ),
        ]),
    )
    .await;
}

#[tokio::test]
async fn a_fresh_start_kills_the_abandoned_cursor() {
    let (port, server) = spawn_server(abandon_server);
    let mut connection = connection_for(port).await;

    let first = connection
        .find_page_start("c1", &Document::new(), 2)
        .await
        .expect("first batch");
    assert!(first.suspended);

    let fresh = connection
        .find_page_start("c1", &Document::new(), 2)
        .await
        .expect("fresh batch");
    assert!(!fresh.suspended, "cursor id 0 completes the flow");

    // The abandoned cursor state is gone either way.
    let error = connection
        .find_page_continue()
        .await
        .expect_err("no cursor");
    assert!(matches!(
        error,
        ConnectionError::Protocol(ref message) if message.contains("no suspended cursor")
    ));

    connection.terminate().await;
    server.await.expect("server task");
}

/// `limit = 0` degenerates to the fetch-all contract:
/// `singleBatch: true`, no `batchSize`, drained first reply.
async fn fetch_all_server(stream: TcpStream) {
    let mut stream = stream;
    handshake(&mut stream).await;

    let Some((request_id, command)) = read_frame(&mut stream).await else {
        return;
    };
    assert_eq!(first_command(&command), "find");
    assert_eq!(find_field(&command, "singleBatch"), &Bson::Boolean(true));
    assert!(
        !command.iter().any(|(field, _)| field == "batchSize"),
        "fetch-all must not carry a batchSize"
    );
    write_frame(
        &mut stream,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), int32(1)),
            (
                "cursor".to_owned(),
                Bson::Document(cursor_doc(
                    int64(0),
                    "firstBatch",
                    vec![doc_n(1), doc_n(2), doc_n(3)],
                )),
            ),
        ]),
    )
    .await;
    // The connection stays usable afterwards (no suspended cursor).
    let Some((request_id, _command)) = read_frame(&mut stream).await else {
        return;
    };
    write_frame(
        &mut stream,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), int32(1)),
            (
                "cursor".to_owned(),
                Bson::Document(cursor_doc(int64(0), "firstBatch", vec![doc_n(9)])),
            ),
        ]),
    )
    .await;
}

#[tokio::test]
async fn limit_zero_degenerates_to_fetch_all() {
    let (port, server) = spawn_server(fetch_all_server);
    let mut connection = connection_for(port).await;

    let page = connection
        .find_page_start("c1", &Document::new(), 0)
        .await
        .expect("all");
    assert!(!page.suspended);
    assert_eq!(page.total, 3);
    // limit=0 answers in one batch: no cursor to continue.
    let error = connection
        .find_page_continue()
        .await
        .expect_err("no cursor");
    assert!(matches!(
        error,
        ConnectionError::Protocol(ref message) if message.contains("no suspended cursor")
    ));
    // And a terminated abandoned state never leaks: the fresh one-shot
    // find (same contract) works on the same connection.
    let docs = connection
        .find("c1", &Vec::new())
        .await
        .expect("one-shot still works");
    assert_eq!(docs.len(), 1);

    connection.terminate().await;
    server.await.expect("server task");
}

/// Only the handshake: the client must fail locally without sending
/// anything (fail-fast validation), and the connection stays usable.
async fn handshake_only_server(stream: TcpStream) {
    let mut stream = stream;
    handshake(&mut stream).await;
    // Nothing else is scripted; an unexpected command is answered with
    // a command failure (never a panic, never a hang).
    loop {
        let Some((request_id, _command)) = read_frame(&mut stream).await else {
            return;
        };
        write_frame(
            &mut stream,
            request_id,
            &Document::from(vec![
                ("ok".to_owned(), Bson::Double(0.0)),
                ("code".to_owned(), int32(59)),
                (
                    "errmsg".to_owned(),
                    Bson::String("command not handled".to_owned()),
                ),
            ]),
        )
        .await;
    }
}

#[tokio::test]
async fn validation_fails_fast_and_keeps_the_connection() {
    let (port, server) = spawn_server(handshake_only_server);
    let mut connection = connection_for(port).await;

    let error = connection
        .find_page_start("c1", &Document::new(), -1)
        .await
        .expect_err("negative limit");
    assert!(matches!(
        error,
        ConnectionError::Protocol(ref message) if message.contains("negative batch size")
    ));
    let error = connection
        .find_page_continue()
        .await
        .expect_err("no cursor");
    assert!(matches!(
        error,
        ConnectionError::Protocol(ref message) if message.contains("no suspended cursor")
    ));

    // The connection is untouched: a valid fetch-all flows normally.
    let page = connection.find_page_start("c1", &Document::new(), 0).await;
    // The scripted server rejects every command; what matters is that
    // the failure is a server command failure, not a local one.
    assert!(matches!(page, Err(ConnectionError::ExecutionFailed { .. })));

    connection.terminate().await;
    let _ = server.await;
}

/// A failing getMore aborts the page flow and clears the cursor state.
async fn failing_get_more_server(stream: TcpStream) {
    let mut stream = stream;
    handshake(&mut stream).await;
    let Some((request_id, _command)) = read_frame(&mut stream).await else {
        return;
    };
    write_frame(
        &mut stream,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), int32(1)),
            (
                "cursor".to_owned(),
                Bson::Document(cursor_doc(int64(99), "firstBatch", vec![doc_n(1)])),
            ),
        ]),
    )
    .await;
    let Some((request_id, _command)) = read_frame(&mut stream).await else {
        return;
    };
    write_frame(
        &mut stream,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), Bson::Double(0.0)),
            ("code".to_owned(), int32(96)),
            (
                "errmsg".to_owned(),
                Bson::String("cursor is dead".to_owned()),
            ),
        ]),
    )
    .await;
}

#[tokio::test]
async fn a_failing_get_more_clears_the_suspended_cursor() {
    let (port, server) = spawn_server(failing_get_more_server);
    let mut connection = connection_for(port).await;

    connection
        .find_page_start("c1", &Document::new(), 2)
        .await
        .expect("first batch suspends");
    let error = connection
        .find_page_continue()
        .await
        .expect_err("getMore fails");
    assert!(matches!(error, ConnectionError::ExecutionFailed { .. }));

    // The flow died: no suspended cursor state survives the failure.
    let error = connection
        .find_page_continue()
        .await
        .expect_err("no cursor");
    assert!(matches!(
        error,
        ConnectionError::Protocol(ref message) if message.contains("no suspended cursor")
    ));

    connection.terminate().await;
    server.await.expect("server task");
}
