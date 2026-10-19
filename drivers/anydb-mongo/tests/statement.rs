//! The `find <collection> with <filter-text>` statement surface: filter
//! text compiles to a BSON document client-side with `?` parameters
//! bound to typed values. The fake mongod asserts the exact filter
//! document it received and applies a tiny matcher to its dataset, so
//! the tests prove the filter travels, binds, and actually filters.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use anydb_mongo::WireDataSource;
use anydb_mongo::bson::{Bson, Document};
use anydb_mongo::uri::parse_target;
use anydb_shared::ConnectionError;
use anydb_shared::driver::spi::DataSource as _;
use anydb_shared::driver::statement::{QueryParameter, TypedValue};

// ---------- wire helpers on the fake server (same shape as paging.rs) --

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(i32, Document)> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await.ok()?;
    let length = i32::from_le_bytes(header[0..4].try_into().expect("4 bytes"));
    let request_id = i32::from_le_bytes(header[4..8].try_into().expect("4 bytes"));
    let mut body = vec![0u8; (length - 16) as usize];
    stream.read_exact(&mut body).await.ok()?;
    Some((
        request_id,
        if body.get(4) == Some(&0x00) {
            anydb_mongo::bson::parse_document(&body[5..]).ok()?
        } else {
            return None;
        },
    ))
}

async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, response_to: i32, body: &Document) {
    let document = anydb_mongo::bson::encode_document(body).expect("reply encodes");
    let length = (21 + document.len()) as i32;
    let mut out = Vec::with_capacity(length as usize);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&2i32.to_le_bytes());
    out.extend_from_slice(&response_to.to_le_bytes());
    out.extend_from_slice(&2013i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.push(0x00);
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

fn find_reply_body(batch: Vec<Document>, cursor_id: i64) -> Document {
    Document::from(vec![
        ("ok".to_owned(), int32(1)),
        (
            "cursor".to_owned(),
            Bson::Document(cursor_doc(int64(cursor_id), "firstBatch", batch)),
        ),
    ])
}

fn get_more_reply_body(batch: Vec<Document>, cursor_id: i64) -> Document {
    Document::from(vec![
        ("ok".to_owned(), int32(1)),
        (
            "cursor".to_owned(),
            Bson::Document(cursor_doc(int64(cursor_id), "nextBatch", batch)),
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
                Bson::String("8.0.0-fake-statement".to_owned()),
            ),
        ]),
    )
    .await;
}

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

fn source_for(port: u16) -> impl Future<Output = std::sync::Arc<WireDataSource>> {
    let target = parse_target(&format!("mongodb://127.0.0.1:{port}"), None).expect("target parses");
    async move { WireDataSource::open(&target).await.expect("open") }
}

// ---------- server-side matcher (only what the scripts exercise) -------

/// Top-level `$or`/`$and`/`$nor` keys are mongo's connective operators;
/// any other key applies its operator condition to the field value. A
/// scalar condition is equality (mongo's natural shorthand).
fn matches_filter(filter: &Document, document: &Document) -> bool {
    filter.iter().all(|(path, condition)| match path.as_str() {
        "$or" => match condition {
            Bson::Array(branches) => branches.iter().any(|branch| match branch {
                Bson::Document(branch_document) => matches_filter(branch_document, document),
                _ => false,
            }),
            _ => false,
        },
        // A `$nor` holds when no branch matches.
        "$nor" => match condition {
            Bson::Array(branches) => branches.iter().all(|branch| match branch {
                Bson::Document(branch_document) => !matches_filter(branch_document, document),
                _ => true,
            }),
            _ => false,
        },
        "$and" => match condition {
            Bson::Array(branches) => branches.iter().all(|branch| match branch {
                Bson::Document(branch_document) => matches_filter(branch_document, document),
                _ => false,
            }),
            _ => false,
        },
        _ => {
            let value = field_value(document, path);
            match condition {
                Bson::Document(operators) => {
                    !operators.is_empty()
                        && operators
                            .iter()
                            .all(|(op, operand)| match_op(op, value, operand))
                }
                scalar => match_op("$eq", value, scalar),
            }
        }
    })
}

/// Dotted-path lookup descending through embedded documents.
fn field_value<'a>(document: &'a Document, path: &str) -> Option<&'a Bson> {
    let mut segments = path.split('.');
    let first = segments.next()?;
    let mut current = document
        .iter()
        .find(|(field, _)| field == first)
        .map(|(_, value)| value)?;
    for segment in segments {
        match current {
            Bson::Document(nested) => {
                current = nested
                    .iter()
                    .find(|(field, _)| field == segment)
                    .map(|(_, value)| value)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

fn match_op(op: &str, value: Option<&Bson>, operand: &Bson) -> bool {
    match op {
        "$eq" => value.is_some_and(|value| values_equal(value, operand)),
        "$ne" => !value.is_some_and(|value| values_equal(value, operand)),
        // `$not` inverts exactly one operator expression: the negation
        // of a missing field is true (mongo matches absent fields).
        "$not" => match operand {
            Bson::Document(inner) => match inner.iter().next() {
                Some((inner_op, inner_operand)) => !match_op(inner_op, value, inner_operand),
                None => false,
            },
            _ => false,
        },
        "$in" => match operand {
            Bson::Array(list) => {
                value.is_some_and(|value| list.iter().any(|item| values_equal(value, item)))
            }
            _ => false,
        },
        "$gt" | "$lt" | "$lte" | "$gte" => {
            match value.and_then(|value| values_compare(value, operand)) {
                Some(ordering) => match op {
                    "$gt" => ordering == std::cmp::Ordering::Greater,
                    "$lt" => ordering == std::cmp::Ordering::Less,
                    "$lte" => ordering != std::cmp::Ordering::Greater,
                    _ => ordering != std::cmp::Ordering::Less,
                },
                None => false,
            }
        }
        unexpected => panic!("server matcher does not implement {unexpected}"),
    }
}

/// Mongo numeric equality ignores int widths and int/double; strings,
/// booleans and null compare by category.
fn values_equal(a: &Bson, b: &Bson) -> bool {
    if let (Some(x), Some(y)) = (as_number(a), as_number(b)) {
        return x == y;
    }
    match (a, b) {
        (Bson::String(x), Bson::String(y)) => x == y,
        (Bson::Boolean(x), Bson::Boolean(y)) => x == y,
        (Bson::Null, Bson::Null) => true,
        _ => false,
    }
}

/// Numeric or lexicographic ordering; `None` when the categories differ.
fn values_compare(a: &Bson, b: &Bson) -> Option<std::cmp::Ordering> {
    if let (Some(x), Some(y)) = (as_number(a), as_number(b)) {
        return x.partial_cmp(&y);
    }
    match (a, b) {
        (Bson::String(x), Bson::String(y)) => Some(x.cmp(y)),
        (Bson::Boolean(x), Bson::Boolean(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn as_number(value: &Bson) -> Option<f64> {
    match value {
        Bson::Int32(value) => Some(f64::from(*value)),
        Bson::Int64(value) => Some(*value as f64),
        Bson::Double(value) => Some(*value),
        _ => None,
    }
}

// ---------- datasets and scripted handlers -----------------------------

fn doc_n(n: i32, tag: &str, flag: bool) -> Document {
    Document::from(vec![
        ("n".to_owned(), int32(n)),
        ("tag".to_owned(), Bson::String(tag.to_owned())),
        ("flag".to_owned(), Bson::Boolean(flag)),
    ])
}

fn doc_txt(n: i32, txt: &str) -> Document {
    Document::from(vec![
        ("n".to_owned(), int32(n)),
        ("txt".to_owned(), Bson::String(txt.to_owned())),
    ])
}

/// Serves ONE find: asserts the exact compiled filter document, applies
/// the matcher to the dataset, and answers in one drained batch. The
/// caller supplies the expected narrowing count to keep the test from
/// ever passing through a no-op filter.
async fn filter_find_server(
    stream: TcpStream,
    expected_filter: Bson,
    dataset: Vec<Document>,
    expected_matches: usize,
) {
    let mut stream = stream;
    handshake(&mut stream).await;

    let Some((request_id, command)) = read_frame(&mut stream).await else {
        panic!("find read");
    };
    assert_eq!(first_command(&command), "find");
    assert_eq!(find_field(&command, "find"), &Bson::String("c1".to_owned()));
    assert_eq!(
        find_field(&command, "filter"),
        &expected_filter,
        "the server must receive the exact compiled filter"
    );
    let filter = match find_field(&command, "filter") {
        Bson::Document(filter) => filter.clone(),
        other => panic!("filter must be a document, got {other:?}"),
    };
    let batch: Vec<Document> = dataset
        .into_iter()
        .filter(|document| matches_filter(&filter, document))
        .collect();
    assert_eq!(
        batch.len(),
        expected_matches,
        "the filter must narrow the dataset"
    );
    write_frame(&mut stream, request_id, &find_reply_body(batch, 0)).await;
}

/// `filter` paged: find with `batchSize 2` keeps cursor id 42 for one
/// getMore round; getMore must NOT carry a filter (only find does) and
/// the final reply drains the id to 0.
async fn paged_filter_server(stream: TcpStream, expected_filter: Bson, dataset: Vec<Document>) {
    let mut stream = stream;
    handshake(&mut stream).await;

    // find with batchSize 2.
    let Some((request_id, command)) = read_frame(&mut stream).await else {
        panic!("find read");
    };
    assert_eq!(first_command(&command), "find");
    assert_eq!(
        find_field(&command, "filter"),
        &expected_filter,
        "the paged find carries the compiled filter"
    );
    let filter = match find_field(&command, "filter") {
        Bson::Document(filter) => filter.clone(),
        other => panic!("filter must be a document, got {other:?}"),
    };
    let batch: Vec<Document> = dataset
        .iter()
        .filter(|document| matches_filter(&filter, document))
        .cloned()
        .collect();
    assert_eq!(batch.len(), 3, "three documents survive the filter");
    write_frame(
        &mut stream,
        request_id,
        &find_reply_body(batch.iter().take(2).cloned().collect(), 42),
    )
    .await;

    // getMore: same id, no filter field, final batch drains to 0.
    let Some((request_id, command)) = read_frame(&mut stream).await else {
        panic!("getMore read");
    };
    assert_eq!(
        find_field(&command, "getMore"),
        &int64(42),
        "the getMore keeps the SAME cursor id"
    );
    assert!(
        !command.iter().any(|(field, _)| field == "filter"),
        "getMore must not carry a filter"
    );
    write_frame(
        &mut stream,
        request_id,
        &get_more_reply_body(batch.iter().skip(2).cloned().collect(), 0),
    )
    .await;
}

/// Handshake-only server: a find arriving HERE means the client failed
/// to reject a statement client-side; the reply makes that failure a
/// visible assertion instead of a hang.
async fn handshake_only_server(stream: TcpStream) {
    let mut stream = stream;
    handshake(&mut stream).await;
    if let Some((request_id, _)) = read_frame(&mut stream).await {
        write_frame(
            &mut stream,
            request_id,
            &Document::from(vec![
                ("ok".to_owned(), int32(0)),
                (
                    "errmsg".to_owned(),
                    Bson::String(
                        "find must never arrive: the statement is invalid client-side".to_owned(),
                    ),
                ),
            ]),
        )
        .await;
    }
}

// ---------- tests -------------------------------------------------------

/// The `'ok': 0` fallback of the handshake-only server must map to a
/// server failure, NOT the protocol error shape the tests below expect.
fn protocol_error(error: ConnectionError, needle: &str) -> bool {
    matches!(error, ConnectionError::Protocol(ref message) if message.contains(needle))
}

#[tokio::test]
async fn literal_equality_filters_server_side() {
    let dataset = vec![
        doc_n(1, "a", true),
        doc_n(2, "b", false),
        doc_n(3, "c", true),
        doc_n(4, "d", false),
    ];
    let (port, server) = spawn_server(move |stream| {
        filter_find_server(
            stream,
            Bson::Document(vec![("n".to_owned(), int32(3))]),
            dataset,
            1,
        )
    });
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed("find c1 with n = 3", &[])
        .await
        .expect("typed execution");
    assert_eq!(
        typed.columns,
        vec!["n".to_owned(), "tag".to_owned(), "flag".to_owned()]
    );
    assert_eq!(
        typed.rows,
        vec![vec![
            Some(TypedValue::Int4(3)),
            Some(TypedValue::Text("c".to_owned())),
            Some(TypedValue::Boolean(true)),
        ]]
    );
    assert_eq!(typed.command_tag, Some("find 1".to_owned()));
    assert_eq!(typed.affected_rows, Some(1));

    server.await.expect("server task");
}

#[tokio::test]
async fn parameterized_range_merges_into_one_operator_document() {
    let dataset = (1..=6).map(|n| doc_n(n, "t", true)).collect::<Vec<_>>();
    let (port, server) = spawn_server(move |stream| {
        filter_find_server(
            stream,
            Bson::Document(vec![(
                "n".to_owned(),
                Bson::Document(vec![
                    ("$gt".to_owned(), int64(3)),
                    ("$lt".to_owned(), int64(5)),
                ]),
            )]),
            dataset,
            1,
        )
    });
    let source = source_for(port).await;

    // Integer params bind as Int64 per the SPI widest-integer contract.
    let typed = source
        .execute_statement_typed(
            "find c1 with n > ? and n < ?",
            &[QueryParameter::Integer(3), QueryParameter::Integer(5)],
        )
        .await
        .expect("typed execution");
    assert_eq!(typed.rows.len(), 1);
    assert_eq!(typed.rows[0][0], Some(TypedValue::Int4(4)));

    server.await.expect("server task");
}

#[tokio::test]
async fn in_list_binds_params_and_literals() {
    let dataset = vec![
        doc_n(1, "a", true),
        doc_n(2, "b", false),
        doc_n(3, "c", true),
        doc_n(4, "d", false),
    ];
    let (port, server) = spawn_server(move |stream| {
        filter_find_server(
            stream,
            Bson::Document(vec![(
                "tag".to_owned(),
                Bson::Document(vec![(
                    "$in".to_owned(),
                    Bson::Array(vec![
                        Bson::String("b".to_owned()),
                        Bson::String("d".to_owned()),
                    ]),
                )]),
            )]),
            dataset,
            2,
        )
    });
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed(
            "find c1 with tag in (?, 'd')",
            &[QueryParameter::Text("b".to_owned())],
        )
        .await
        .expect("typed execution");
    let tags: Vec<String> = typed
        .rows
        .iter()
        .map(|row| match &row[1] {
            Some(TypedValue::Text(tag)) => tag.clone(),
            other => panic!("unexpected tag value {other:?}"),
        })
        .collect();
    assert_eq!(tags, vec!["b".to_owned(), "d".to_owned()]);

    server.await.expect("server task");
}

#[tokio::test]
async fn quote_escaping_travels_byte_by_byte() {
    let dataset = vec![doc_txt(1, "plain"), doc_txt(2, "o'clock")];
    let (port, server) = spawn_server(move |stream| {
        filter_find_server(
            stream,
            Bson::Document(vec![("txt".to_owned(), Bson::String("o'clock".to_owned()))]),
            dataset,
            1,
        )
    });
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed("find c1 with txt = 'o''clock'", &[])
        .await
        .expect("typed execution");
    assert_eq!(typed.rows.len(), 1);
    assert_eq!(
        typed.rows[0][1],
        Some(TypedValue::Text("o'clock".to_owned()))
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn boolean_params_filter_flags() {
    let dataset = vec![
        doc_n(1, "a", true),
        doc_n(2, "b", false),
        doc_n(3, "c", false),
    ];
    let (port, server) = spawn_server(move |stream| {
        filter_find_server(
            stream,
            Bson::Document(vec![("flag".to_owned(), Bson::Boolean(false))]),
            dataset,
            2,
        )
    });
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed("find c1 with flag = ?", &[QueryParameter::Boolean(false)])
        .await
        .expect("typed execution");
    assert_eq!(typed.rows.len(), 2);

    server.await.expect("server task");
}

#[tokio::test]
async fn or_filters_match_either_branch_server_side() {
    let dataset = vec![
        doc_n(1, "a", true),
        doc_n(2, "b", false),
        doc_n(3, "c", true),
        doc_n(4, "d", false),
    ];
    let (port, server) = spawn_server(move |stream| {
        // `tag = 'a' or (n in (2, 3) and flag = ?)` compiles to one
        // `$or` over two branch documents; the second branch merges
        // its `in` and flag conditions conjunctively.
        filter_find_server(
            stream,
            Bson::Document(vec![(
                "$or".to_owned(),
                Bson::Array(vec![
                    Bson::Document(vec![("tag".to_owned(), Bson::String("a".to_owned()))]),
                    Bson::Document(vec![
                        (
                            "n".to_owned(),
                            Bson::Document(vec![(
                                "$in".to_owned(),
                                Bson::Array(vec![Bson::Int32(2), Bson::Int32(3)]),
                            )]),
                        ),
                        ("flag".to_owned(), Bson::Boolean(true)),
                    ]),
                ]),
            )]),
            dataset,
            2,
        )
    });
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed(
            "find c1 with tag = 'a' or (n in (2, 3) and flag = ?)",
            &[QueryParameter::Boolean(true)],
        )
        .await
        .expect("typed execution");
    // Branch 1 keeps n=1; branch 2 keeps n=3 (n=2 fails the flag).
    let numbers: Vec<i32> = typed
        .rows
        .iter()
        .map(|row| match &row[0] {
            Some(TypedValue::Int4(n)) => *n,
            other => panic!("unexpected number value {other:?}"),
        })
        .collect();
    assert_eq!(numbers, vec![1, 3], "each branch contributes its matches");

    server.await.expect("server task");
}

#[tokio::test]
async fn not_filters_negate_server_side() {
    let dataset = vec![
        doc_n(1, "a", true),
        doc_n(2, "a", false),
        doc_n(3, "b", true),
        doc_n(4, "d", false),
    ];
    let (port, server) = spawn_server(move |stream| {
        // `flag = true and not (n > 3 or tag = 'b')` compiles to the
        // merged flag slot plus one `$nor` branch document beside it.
        filter_find_server(
            stream,
            Bson::Document(vec![
                ("flag".to_owned(), Bson::Boolean(true)),
                (
                    "$nor".to_owned(),
                    Bson::Array(vec![
                        Bson::Document(vec![(
                            "n".to_owned(),
                            Bson::Document(vec![("$gt".to_owned(), Bson::Int32(3))]),
                        )]),
                        Bson::Document(vec![("tag".to_owned(), Bson::String("b".to_owned()))]),
                    ]),
                ),
            ]),
            dataset,
            1,
        )
    });
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed("find c1 with flag = true and not (n > 3 or tag = 'b')", &[])
        .await
        .expect("typed execution");
    // flag=true keeps n1, n3; the $nor drops tag='b' (n3) and n>3 off
    // the candidates, leaving exactly n1.
    let numbers: Vec<i32> = typed
        .rows
        .iter()
        .map(|row| match &row[0] {
            Some(TypedValue::Int4(n)) => *n,
            other => panic!("unexpected number value {other:?}"),
        })
        .collect();
    assert_eq!(numbers, vec![1]);

    server.await.expect("server task");
}

#[tokio::test]
async fn arity_errors_never_reach_the_wire() {
    let (port, server) = spawn_server(handshake_only_server);
    let source = source_for(port).await;

    let error = source
        .execute_statement_typed("find c1 with n = ?", &[])
        .await
        .expect_err("missing parameter");
    assert!(
        protocol_error(error, "expects 1 parameter"),
        "arity failures are client-side protocol errors raised BEFORE any wire write"
    );

    let error = source
        .execute_statement_typed(
            "find c1 with n = ? and flag = ?",
            &[QueryParameter::Integer(1)],
        )
        .await
        .expect_err("missing parameter");
    assert!(protocol_error(error, "expects 2 parameter(s), got 1"));

    // A statement without a 'with' filter takes no parameters, always.
    let error = source
        .execute_statement_typed("find c1", &[QueryParameter::Integer(1)])
        .await
        .expect_err("params refused");
    assert!(protocol_error(
        error,
        "without a 'with' filter take no parameters"
    ));

    // The handshake-only server task blocks on its next read forever by
    // design (no further frames must EVER arrive): its completion cannot
    // be awaited here.
    drop(server);
}

#[tokio::test]
async fn paged_find_carries_the_filter_and_get_more_does_not() {
    let dataset = vec![
        doc_n(1, "a", true),
        doc_n(2, "b", false),
        doc_n(3, "b", true),
        doc_n(4, "c", false),
        doc_n(5, "b", true),
    ];
    let expected = Bson::Document(vec![("tag".to_owned(), Bson::String("b".to_owned()))]);
    let (port, server) = spawn_server(move |stream| paged_filter_server(stream, expected, dataset));
    let source = source_for(port).await;

    let first = source
        .query_page_start("find c1 with tag = 'b'", &[], 2)
        .await
        .expect("first batch");
    assert!(first.suspended);
    assert_eq!(first.result.rows.len(), 2);
    assert_eq!(first.result.affected_rows, None, "no tag while suspended");

    let last = source.query_page_continue().await.expect("final batch");
    assert!(!last.suspended, "the drained reply completes the flow");
    assert_eq!(last.result.rows.len(), 1);
    assert_eq!(
        last.result.command_tag,
        Some("find 3".to_owned()),
        "the drained batch carries the accumulated total"
    );
    assert_eq!(last.result.affected_rows, Some(3));

    server.await.expect("server task");
}
