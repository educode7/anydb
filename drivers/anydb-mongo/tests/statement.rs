//! The mongo statement surface: `find <collection> with <filter-text>`,
//! `insert <collection> with <json-document>`,
//! `delete <collection> with <filter-text>` and
//! `update <collection> with <filter-text> set <json-document>`.
//!
//! Filters compile to a BSON document client-side with `?` parameters
//! bound to typed values. The fake mongod asserts the exact filter
//! document it received and applies a tiny matcher to its dataset, so
//! the tests prove the filter travels, binds, and actually filters.
//!
//! The insert half proves the parsed JSON document reaches the wire as
//! the command's only element, that a server write error stays an
//! error, and that every insert failure is client-side (the
//! handshake-only server panics on any command, so a Protocol verdict
//! there proves no frame was ever written).
//!
//! The delete/update half proves the destructive write surface: the
//! delete travels only behind the confirmed execution seam (the
//! ordinary typed surface refuses pre-wire), the update spec travels
//! verbatim with upsert off and multi on, both results carry a legible
//! acceptance message, and the update's `set` separator never splits a
//! quoted filter value.

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
/// booleans and null compare by category; decimal equality is
/// representational in the fake (both sides arrive from the same
/// parse) — the real mongod compares decimals numerically across
/// encodings, which the live smoke adjudicates.
fn values_equal(a: &Bson, b: &Bson) -> bool {
    if let (Some(x), Some(y)) = (as_number(a), as_number(b)) {
        return x == y;
    }
    match (a, b) {
        (Bson::Decimal128(x), Bson::Decimal128(y)) => x == y,
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

fn doc_v(n: i32, v: Bson) -> Document {
    Document::from(vec![("n".to_owned(), int32(n)), ("v".to_owned(), v)])
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

#[tokio::test]
async fn decimal_params_filter_exact_decimal_values() {
    use anydb_mongo::bson::parse_decimal128;

    let decimal = |text: &str| Bson::Decimal128(parse_decimal128(text).expect("decimal literal"));
    let dataset = vec![
        doc_v(1, decimal("123.456")),
        doc_v(2, decimal("2.50")),
        doc_v(3, Bson::Double(123.456)),
    ];
    let (port, server) = spawn_server(move |stream| {
        filter_find_server(
            stream,
            Bson::Document(vec![("v".to_owned(), decimal("123.456"))]),
            dataset,
            1,
        )
    });
    let source = source_for(port).await;

    // The bind side runs the same parse the decode side produced
    // TypedValue::BigDecimal from: equality is exact, the binary double
    // approximation cannot confuse the decimal match.
    let typed = source
        .execute_statement_typed(
            "find c1 with v = ?",
            &[QueryParameter::BigDecimal("123.456".to_owned())],
        )
        .await
        .expect("typed execution");
    assert_eq!(typed.rows.len(), 1);
    match &typed.rows[0][1] {
        Some(TypedValue::BigDecimal(text)) => assert_eq!(text, "123.456"),
        other => panic!("unexpected value {other:?}"),
    }

    server.await.expect("server task");
}

// ---------- insert statement surface ---------------------------------

/// A field lookup with wording that fits any command (the find-side
/// helper's panic message names `find`).
fn field<'a>(command: &'a Document, key: &str) -> &'a Bson {
    command
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("the command carries {key}"))
}

fn insert_reply(inserted: i32) -> Document {
    Document::from(vec![
        ("ok".to_owned(), int32(1)),
        ("n".to_owned(), int32(inserted)),
    ])
}

/// Handshake + exactly one `insert` command: asserts the full wire
/// shape (command name, target collection, `$db`, and the documents
/// array carrying the parsed document verbatim), then replies.
async fn insert_server(stream: TcpStream, expected: Document, reply: Document) {
    let mut stream = stream;
    handshake(&mut stream).await;
    let Some((request_id, command)) = read_frame(&mut stream).await else {
        panic!("insert command read");
    };
    assert_eq!(first_command(&command), "insert");
    assert_eq!(
        field(&command, "insert"),
        &Bson::String("components".to_owned()),
        "the command targets the statement's collection"
    );
    assert_eq!(
        field(&command, "documents"),
        &Bson::Array(vec![Bson::Document(expected)]),
        "documents carries the parsed JSON document as its only element"
    );
    assert_eq!(
        field(&command, "$db"),
        &Bson::String("admin".to_owned()),
        "every OP_MSG request carries the $db argument"
    );
    write_frame(&mut stream, request_id, &reply).await;
}

#[tokio::test]
async fn insert_statement_ships_the_parsed_document() {
    let expected: Document = vec![
        ("codeGroup".to_owned(), Bson::String("1".to_owned())),
        ("isActive".to_owned(), Bson::String("1".to_owned())),
        (
            "listComponent".to_owned(),
            Bson::Array(vec![Bson::Document(vec![(
                "codeComponent".to_owned(),
                Bson::String("1".to_owned()),
            )])]),
        ),
        ("hasModal".to_owned(), Bson::Boolean(true)),
        (
            "modalOptions".to_owned(),
            Bson::Array(vec![Bson::Document(vec![
                (
                    "title".to_owned(),
                    Bson::String("Mercancías Restringidas".to_owned()),
                ),
                (
                    "authenticationType".to_owned(),
                    Bson::String("AUTH1_AUTH2".to_owned()),
                ),
            ])]),
        ),
    ];
    let (port, server) =
        spawn_server(move |stream| insert_server(stream, expected, insert_reply(1)));
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed(
            r#"insert components with {"codeGroup":"1","isActive":"1","listComponent":[{"codeComponent":"1"}],"hasModal":true,"modalOptions":[{"title":"Mercancías Restringidas","authenticationType":"AUTH1_AUTH2"}]}"#,
            &[],
        )
        .await
        .expect("insert executes");
    assert!(
        typed.columns.is_empty(),
        "an insert yields no result columns, got {:?}",
        typed.columns
    );
    assert!(
        typed.rows.is_empty(),
        "an insert yields no result rows, got {:?}",
        typed.rows
    );
    assert_eq!(typed.command_tag, Some("insert 1".to_owned()));
    assert_eq!(typed.affected_rows, Some(1));

    server.await.expect("server task");
}

#[tokio::test]
async fn insert_write_errors_stay_errors() {
    let write_error: Document = vec![
        ("index".to_owned(), int32(0)),
        ("code".to_owned(), int32(11000)),
        (
            "errmsg".to_owned(),
            Bson::String(
                "E11000 duplicate key error collection: vuce-landing.components index: _id_"
                    .to_owned(),
            ),
        ),
    ];
    let reply = Document::from(vec![
        ("ok".to_owned(), int32(1)),
        ("n".to_owned(), int32(0)),
        (
            "writeErrors".to_owned(),
            Bson::Array(vec![Bson::Document(write_error)]),
        ),
    ]);
    let (port, server) =
        spawn_server(move |stream| insert_server(stream, vec![("a".to_owned(), int32(1))], reply));
    let source = source_for(port).await;

    let error = source
        .execute_statement_typed(r#"insert components with {"a":1}"#, &[])
        .await
        .expect_err("a write error must not read as a successful insert");
    assert!(
        matches!(
            &error,
            ConnectionError::ExecutionFailed { message, .. } if message.contains("E11000")
        ),
        "the server's write errmsg surfaces, got {error:?}"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn insert_failures_never_reach_the_wire() {
    let (port, server) = spawn_server(handshake_only_server);
    let source = source_for(port).await;

    // Parameters: the document IS the payload, there is nothing to bind.
    let error = source
        .execute_statement_typed(r#"insert c1 with {"a":1}"#, &[QueryParameter::Integer(1)])
        .await
        .expect_err("parameters refused");
    assert!(
        protocol_error(error, "insert statements take no parameters"),
        "a parameterized insert is a client-side protocol error"
    );

    // Syntax: malformed JSON, a non-object top level, a missing
    // collection — all resolved before any frame exists.
    let error = source
        .execute_statement_typed("insert components with {not json}", &[])
        .await
        .expect_err("malformed document");
    assert!(protocol_error(error, "mongo insert document"));

    let error = source
        .execute_statement_typed(r#"insert components with [{"a":1}]"#, &[])
        .await
        .expect_err("a top-level array is not a document");
    assert!(protocol_error(error, "expected a JSON object"));

    let error = source
        .execute_statement_typed("insert", &[])
        .await
        .expect_err("missing collection");
    assert!(protocol_error(
        error,
        "mongo statements are 'find <collection> [with <filter>]', 'insert <collection> with <document>', 'delete [one] <collection> with <filter>' or 'update [one] <collection> with <filter> set <document>'"
    ));

    // The handshake-only server answers `ok: 0` to any command it does
    // receive, so a Protocol verdict above proves nothing was sent.
    drop(server);
}

#[tokio::test]
async fn paging_rejects_insert_statements() {
    let (port, server) = spawn_server(handshake_only_server);
    let source = source_for(port).await;

    let error = source
        .query_page_start(r#"insert c1 with {"a":1}"#, &[], 10)
        .await
        .expect_err("an insert has no cursor to page");
    assert!(
        protocol_error(error, "cursor paging requires a find statement"),
        "paging must reject the statement client-side, got nothing"
    );

    drop(server);
}

// ---------- delete / update write statements --------------------------

fn delete_reply(removed: i32) -> Document {
    Document::from(vec![
        ("ok".to_owned(), int32(1)),
        ("n".to_owned(), int32(removed)),
    ])
}

fn update_reply(matched: i32, modified: i32) -> Document {
    Document::from(vec![
        ("ok".to_owned(), int32(1)),
        ("n".to_owned(), int32(matched)),
        ("nModified".to_owned(), int32(modified)),
    ])
}

/// Handshake + exactly one `delete` command: asserts the full wire
/// shape (the compiled filter as the only selector with the expected
/// limit — `0` all-matching, `1` single-document, the `$db` argument),
/// then replies.
async fn delete_server(
    stream: TcpStream,
    expected_filter: Document,
    expected_limit: i32,
    reply: Document,
) {
    let mut stream = stream;
    handshake(&mut stream).await;
    let Some((request_id, command)) = read_frame(&mut stream).await else {
        panic!("delete command read");
    };
    assert_eq!(first_command(&command), "delete");
    assert_eq!(
        field(&command, "delete"),
        &Bson::String("components".to_owned()),
        "the command targets the statement's collection"
    );
    assert_eq!(
        field(&command, "deletes"),
        &Bson::Array(vec![Bson::Document(vec![
            ("q".to_owned(), Bson::Document(expected_filter)),
            ("limit".to_owned(), int32(expected_limit)),
        ])]),
        "deletes carries the compiled filter as the only selector \
         with the statement's limit"
    );
    assert_eq!(
        field(&command, "$db"),
        &Bson::String("admin".to_owned()),
        "every OP_MSG request carries the $db argument"
    );
    write_frame(&mut stream, request_id, &reply).await;
}

/// Handshake + exactly one `update` command: asserts the update spec
/// (`u`) travels verbatim with `upsert: false` and the statement's
/// `multi` flag (`true` all-matching, `false` single-document) plus the
/// compiled filter as the only selector, then replies.
async fn update_server(
    stream: TcpStream,
    expected_filter: Document,
    expected_update: Document,
    expected_multi: bool,
    reply: Document,
) {
    let mut stream = stream;
    handshake(&mut stream).await;
    let Some((request_id, command)) = read_frame(&mut stream).await else {
        panic!("update command read");
    };
    assert_eq!(first_command(&command), "update");
    assert_eq!(
        field(&command, "update"),
        &Bson::String("components".to_owned()),
        "the command targets the statement's collection"
    );
    assert_eq!(
        field(&command, "updates"),
        &Bson::Array(vec![Bson::Document(vec![
            ("q".to_owned(), Bson::Document(expected_filter)),
            ("u".to_owned(), Bson::Document(expected_update)),
            ("upsert".to_owned(), Bson::Boolean(false)),
            ("multi".to_owned(), Bson::Boolean(expected_multi)),
        ])]),
        "updates carries the statement's filter and update spec \
         with the never-upserting flag and the statement's multi"
    );
    assert_eq!(
        field(&command, "$db"),
        &Bson::String("admin".to_owned()),
        "every OP_MSG request carries the $db argument"
    );
    write_frame(&mut stream, request_id, &reply).await;
}

#[tokio::test]
async fn delete_removes_every_match_and_says_so() {
    let expected_filter = vec![("n".to_owned(), int32(3))];
    let (port, server) =
        spawn_server(move |stream| delete_server(stream, expected_filter, 0, delete_reply(2)));
    let source = source_for(port).await;

    // The delete travels ONLY behind the confirmed seam.
    let typed = source
        .execute_statement_typed_confirmed("delete components with n = 3", &[])
        .await
        .expect("the confirmed execution runs the delete");
    assert!(typed.columns.is_empty(), "a delete yields no columns");
    assert!(typed.rows.is_empty(), "a delete yields no rows");
    assert_eq!(typed.command_tag, Some("delete 2".to_owned()));
    assert_eq!(typed.affected_rows, Some(2));
    assert_eq!(
        typed.message,
        Some("delete components: 2 document(s) removed".to_owned()),
        "the acceptance names what was wiped in words"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn the_unconfirmed_delete_refuses_and_the_connection_survives() {
    let expected_filter = vec![("n".to_owned(), int32(1))];
    let (port, server) =
        spawn_server(move |stream| delete_server(stream, expected_filter, 0, delete_reply(1)));
    let source = source_for(port).await;

    // The ordinary typed surface refuses BEFORE any wire bytes: the
    // refusals must name the confirmed seam (DBeaver destructive-SQL
    // confirmation analog). The same connection then executes the
    // confirmed delete fine — a refusal is stateless client-side.
    let error = source
        .execute_statement_typed("delete components with n = 1", &[])
        .await
        .expect_err("the ordinary typed surface refuses a delete");
    assert!(
        protocol_error(error, "delete statements are destructive"),
        "the refusal names the destructiveness, got nothing"
    );
    let error = source
        .execute_statement_typed("delete components with n = 1", &[])
        .await
        .expect_err("the ordinary typed surface refuses a delete");
    assert!(
        protocol_error(error, "execute_statement_typed_confirmed"),
        "the refusal names the seam, got nothing"
    );

    let typed = source
        .execute_statement_typed_confirmed("delete components with n = 1", &[])
        .await
        .expect("the confirmed seam runs the delete on a fresh state");
    assert_eq!(typed.command_tag, Some("delete 1".to_owned()));
    assert_eq!(
        typed.message,
        Some("delete components: 1 document(s) removed".to_owned())
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn delete_shapes_beyond_the_wire_never_reach_it() {
    let (port, server) = spawn_server(handshake_only_server);
    let source = source_for(port).await;

    // A filter-less delete would match everything: that shape is not a
    // statement at all, minting the form hint before any frame exists.
    let error = source
        .execute_statement_typed("delete components", &[])
        .await
        .expect_err("a filter-less delete is not a statement");
    assert!(
        protocol_error(
            error,
            "delete statements are 'delete <collection> with <filter>'"
        ),
        "the form hint names the required filter"
    );

    // Wrong arity: the compiled filter has a `?` to bind. A delete's
    // low-level failures surface through the confirmed seam (the
    // ordinary surface answers the seam refusal, always).
    let error = source
        .execute_statement_typed_confirmed("delete components with n = ?", &[])
        .await
        .expect_err("missing parameter");
    assert!(
        protocol_error(error, "statement expects 1 parameter(s), got 0"),
        "the compiled filter binds before anything is sent"
    );

    drop(server);
}

#[tokio::test]
async fn a_bound_delete_filters_with_the_parameter() {
    let expected_filter = vec![("n".to_owned(), Bson::Int64(4))];
    let (port, server) =
        spawn_server(move |stream| delete_server(stream, expected_filter, 0, delete_reply(0)));
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed_confirmed(
            "delete components with n = ?",
            &[QueryParameter::Integer(4)],
        )
        .await
        .expect("the bound delete executes");
    assert_eq!(typed.command_tag, Some("delete 0".to_owned()));
    assert_eq!(
        typed.message,
        Some("delete components: 0 document(s) removed".to_owned()),
        "a zero-delete is still an explicit, visible acceptance"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn update_applies_the_update_spec_and_says_what_it_touched() {
    let expected_filter = vec![("n".to_owned(), int32(2))];
    let expected_update = vec![(
        "$set".to_owned(),
        Bson::Document(vec![("flag".to_owned(), int32(1))]),
    )];
    let (port, server) = spawn_server(move |stream| {
        update_server(
            stream,
            expected_filter,
            expected_update,
            true,
            update_reply(1, 1),
        )
    });
    let source = source_for(port).await;

    // The update executes from the ORDINARY path (the confirmation seam
    // is scoped to delete): matched and modified arrive separately, in
    // words and in the tag/count contract.
    let typed = source
        .execute_statement_typed(
            r#"update components with n = 2 set {"$set": {"flag": 1}}"#,
            &[],
        )
        .await
        .expect("the update executes");
    assert!(typed.columns.is_empty(), "an update yields no columns");
    assert!(typed.rows.is_empty(), "an update yields no rows");
    assert_eq!(typed.command_tag, Some("update 1".to_owned()));
    assert_eq!(typed.affected_rows, Some(1));
    assert_eq!(
        typed.message,
        Some("update components: 1 matched, 1 modified".to_owned())
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn the_set_separator_never_splits_quoted_filter_values() {
    // Three server cases in a row: single-quoted 'my set version',
    // double-quoted "my set", and the doubled-quote escape 'a''set''b'.
    let cases: Vec<(&str, Document)> = vec![
        (
            r#"update components with tag = 'my set version' set {"$set": {"a": 1}}"#,
            vec![("tag".to_owned(), Bson::String("my set version".to_owned()))],
        ),
        (
            r#"update components with tag = "my set" set {"$set": {"a": 1}}"#,
            vec![("tag".to_owned(), Bson::String("my set".to_owned()))],
        ),
        (
            r#"update components with sig = 'a''set''b' set {"$set": {"a": 1}}"#,
            vec![("sig".to_owned(), Bson::String("a'set'b".to_owned()))],
        ),
    ];
    for (sql, expected_filter) in cases {
        let expected_update = vec![(
            "$set".to_owned(),
            Bson::Document(vec![("a".to_owned(), int32(1))]),
        )];
        let (port, server) = spawn_server(move |stream| {
            update_server(
                stream,
                expected_filter,
                expected_update,
                true,
                update_reply(1, 1),
            )
        });
        let source = source_for(port).await;
        let typed = source
            .execute_statement_typed(sql, &[])
            .await
            .expect("the quoted 'set' stays part of the filter");
        assert_eq!(typed.command_tag, Some("update 1".to_owned()));
        server.await.expect("server task");
    }
}

#[tokio::test]
async fn a_bound_update_filters_with_the_parameter() {
    let expected_filter = vec![("n".to_owned(), Bson::Int64(2))];
    let expected_update = vec![(
        "$set".to_owned(),
        Bson::Document(vec![("flag".to_owned(), int32(1))]),
    )];
    let (port, server) = spawn_server(move |stream| {
        update_server(
            stream,
            expected_filter,
            expected_update,
            true,
            update_reply(2, 2),
        )
    });
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed(
            r#"update components with n = ? set {"$set": {"flag": 1}}"#,
            &[QueryParameter::Integer(2)],
        )
        .await
        .expect("the bound update executes");
    assert_eq!(
        typed.message,
        Some("update components: 2 matched, 2 modified".to_owned())
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn update_failures_never_reach_the_wire() {
    let (port, server) = spawn_server(handshake_only_server);
    let source = source_for(port).await;

    // No `set` clause: the form hint, client-side.
    let error = source
        .execute_statement_typed("update components with n = 2", &[])
        .await
        .expect_err("an update without its set document is not a statement");
    assert!(protocol_error(
        error,
        "update statements are 'update <collection> with <filter> set <document>'"
    ));

    // Malformed JSON after the real `set` separator.
    let error = source
        .execute_statement_typed("update components with n = 2 set {not json}", &[])
        .await
        .expect_err("malformed update document");
    assert!(protocol_error(error, "mongo update document"));

    // A top-level array payload: the update spec is one object.
    let error = source
        .execute_statement_typed(
            r#"update components with n = 2 set [{"$set": {"a": 1}}]"#,
            &[],
        )
        .await
        .expect_err("a top-level array is not an update spec");
    assert!(protocol_error(error, "expected a JSON object"));

    // Wrong arity: the compiled filter has a `?` to bind.
    let error = source
        .execute_statement_typed(
            r#"update components with n = ? set {"$set": {"a": 1}}"#,
            &[],
        )
        .await
        .expect_err("missing parameter");
    assert!(protocol_error(
        error,
        "statement expects 1 parameter(s), got 0"
    ));

    drop(server);
}

#[tokio::test]
async fn update_write_errors_stay_errors() {
    let write_error: Document = vec![
        ("index".to_owned(), int32(0)),
        ("code".to_owned(), int32(11000)),
        (
            "errmsg".to_owned(),
            Bson::String("E11000 duplicate key error collection: admin.components".to_owned()),
        ),
    ];
    let reply = Document::from(vec![
        ("ok".to_owned(), int32(1)),
        ("n".to_owned(), int32(0)),
        ("nModified".to_owned(), int32(0)),
        (
            "writeErrors".to_owned(),
            Bson::Array(vec![Bson::Document(write_error)]),
        ),
    ]);
    let expected_filter = vec![("n".to_owned(), int32(2))];
    let expected_update = vec![(
        "$set".to_owned(),
        Bson::Document(vec![("flag".to_owned(), int32(1))]),
    )];
    let (port, server) = spawn_server(move |stream| {
        update_server(stream, expected_filter, expected_update, true, reply)
    });
    let source = source_for(port).await;

    let error = source
        .execute_statement_typed(
            r#"update components with n = 2 set {"$set": {"flag": 1}}"#,
            &[],
        )
        .await
        .expect_err("a write error must not read as a successful update");
    assert!(
        matches!(
            &error,
            ConnectionError::ExecutionFailed { message, .. } if message.contains("E11000")
        ),
        "the server's write errmsg surfaces, got {error:?}"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn an_update_reply_without_its_modified_count_is_a_protocol_error() {
    let reply = Document::from(vec![
        ("ok".to_owned(), int32(1)),
        ("n".to_owned(), int32(1)),
    ]);
    let expected_filter = vec![("n".to_owned(), int32(2))];
    let expected_update = vec![(
        "$set".to_owned(),
        Bson::Document(vec![("flag".to_owned(), int32(1))]),
    )];
    let (port, server) = spawn_server(move |stream| {
        update_server(stream, expected_filter, expected_update, true, reply)
    });
    let source = source_for(port).await;

    let error = source
        .execute_statement_typed(
            r#"update components with n = 2 set {"$set": {"flag": 1}}"#,
            &[],
        )
        .await
        .expect_err("a missing nModified cannot read as a silent zero");
    assert!(
        protocol_error(error, "the update reply carries no 'nModified' count"),
        "the count context names the update command"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn a_delete_reply_without_its_count_is_a_protocol_error() {
    let reply = Document::from(vec![("ok".to_owned(), int32(1))]);
    let expected_filter = vec![("n".to_owned(), int32(2))];
    let (port, server) =
        spawn_server(move |stream| delete_server(stream, expected_filter, 0, reply));
    let source = source_for(port).await;

    let error = source
        .execute_statement_typed_confirmed("delete components with n = 2", &[])
        .await
        .expect_err("a missing count cannot read as a silent removal");
    assert!(
        protocol_error(error, "the delete reply carries no 'n' count"),
        "the count context names the delete command"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn delete_one_removes_at_most_the_first_match_and_says_so() {
    let expected_filter = vec![("n".to_owned(), int32(2))];
    let (port, server) =
        spawn_server(move |stream| delete_server(stream, expected_filter, 1, delete_reply(1)));
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed_confirmed("delete one components with n = 2", &[])
        .await
        .expect("the confirmed seam runs the single-document delete");
    assert!(typed.columns.is_empty(), "a delete yields no columns");
    assert!(typed.rows.is_empty(), "a delete yields no rows");
    assert_eq!(typed.command_tag, Some("delete 1".to_owned()));
    assert_eq!(typed.affected_rows, Some(1));
    assert_eq!(
        typed.message,
        Some("delete components: 1 document(s) removed".to_owned()),
        "the legible acceptance is the same contract, the limit is wire-side"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn delete_one_wire_limit_comes_from_the_statement_not_the_default() {
    // The reserved-token rule keeps the all-matching form byte-identical:
    // `delete <c> with <f>` still ships limit 0, `delete one <c> with <f>`
    // ships limit 1 with the SAME filter compilation.
    let expected_filter = vec![("n".to_owned(), int32(2))];
    let (port, server) =
        spawn_server(move |stream| delete_server(stream, expected_filter, 0, delete_reply(2)));
    let source = source_for(port).await;
    let typed = source
        .execute_statement_typed_confirmed("delete components with n = 2", &[])
        .await
        .expect("the plain form keeps the remove-all limit");
    assert_eq!(typed.command_tag, Some("delete 2".to_owned()));
    server.await.expect("server task");
}

#[tokio::test]
async fn delete_one_shapes_beyond_the_wire_never_reach_it() {
    let (port, server) = spawn_server(handshake_only_server);
    let source = source_for(port).await;

    // `delete one` alone: no collection after the reserved modifier.
    let error = source
        .execute_statement_typed_confirmed("delete one", &[])
        .await
        .expect_err("the modifier without a collection is not a statement");
    assert!(protocol_error(
        error,
        "delete one statements are 'delete one <collection> with <filter>'"
    ));

    // Missing filter text: the same hint, still client-side.
    let error = source
        .execute_statement_typed_confirmed("delete one components", &[])
        .await
        .expect_err("the single-document form requires its filter too");
    assert!(protocol_error(
        error,
        "delete one statements are 'delete one <collection> with <filter>'"
    ));

    // The gate governs the single-document form too.
    let error = source
        .execute_statement_typed("delete one components with n = 1", &[])
        .await
        .expect_err("the ordinary surface refuses a delete one");
    assert!(
        protocol_error(error, "delete statements are destructive"),
        "the confirmed seam rules every delete form"
    );

    drop(server);
}

#[tokio::test]
async fn update_one_touches_at_most_the_first_match_and_says_so() {
    let expected_filter = vec![("n".to_owned(), int32(2))];
    let expected_update = vec![(
        "$set".to_owned(),
        Bson::Document(vec![("flag".to_owned(), int32(1))]),
    )];
    let (port, server) = spawn_server(move |stream| {
        update_server(
            stream,
            expected_filter,
            expected_update,
            false,
            update_reply(1, 1),
        )
    });
    let source = source_for(port).await;

    // `update one` is reachable from the ORDINARY path: the gate is
    // scoped to delete only.
    let typed = source
        .execute_statement_typed(
            r#"update one components with n = 2 set {"$set": {"flag": 1}}"#,
            &[],
        )
        .await
        .expect("the single-document update executes from the ordinary path");
    assert!(typed.columns.is_empty(), "an update yields no columns");
    assert!(typed.rows.is_empty(), "an update yields no rows");
    assert_eq!(typed.command_tag, Some("update 1".to_owned()));
    assert_eq!(typed.affected_rows, Some(1));
    assert_eq!(
        typed.message,
        Some("update components: 1 matched, 1 modified".to_owned())
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn update_one_wire_multi_flips_but_nothing_else_changes() {
    // Same filter compilation and same `u` contract as the plain form:
    // only `multi` goes false. The driver renders whatever counts the
    // reply carries, verbatim — the (2, 1) reply here is a wire-format
    // fixture, not a live-semantics claim: a live mongod stops at the
    // limit and reports n = 1 for a two-match filter (see the live
    // smoke's surgical leg).
    let expected_filter = vec![("n".to_owned(), int32(2))];
    let expected_update = vec![(
        "$set".to_owned(),
        Bson::Document(vec![("flag".to_owned(), int32(1))]),
    )];
    let (port, server) = spawn_server(move |stream| {
        update_server(
            stream,
            expected_filter,
            expected_update,
            false,
            update_reply(2, 1),
        )
    });
    let source = source_for(port).await;

    let typed = source
        .execute_statement_typed(
            r#"update one components with n = 2 set {"$set": {"flag": 1}}"#,
            &[],
        )
        .await
        .expect("the single-document update executes");
    assert_eq!(
        typed.message,
        Some("update components: 2 matched, 1 modified".to_owned()),
        "the reply counts render verbatim; no fields are dropped or renamed"
    );

    server.await.expect("server task");
}

#[tokio::test]
async fn update_one_shapes_beyond_the_wire_never_reach_it() {
    let (port, server) = spawn_server(handshake_only_server);
    let source = source_for(port).await;

    // `update one` alone: no collection after the reserved modifier.
    let error = source
        .execute_statement_typed("update one", &[])
        .await
        .expect_err("the modifier without a collection is not a statement");
    assert!(protocol_error(
        error,
        "update one statements are 'update one <collection> with <filter> set <document>'"
    ));

    // A collection but no `set` clause: the update-one hint.
    let error = source
        .execute_statement_typed("update one components", &[])
        .await
        .expect_err("the single-document form requires its set clause too");
    assert!(protocol_error(
        error,
        "update one statements are 'update one <collection> with <filter> set <document>'"
    ));

    // Filter requires the same arity contract as the plain form.
    let error = source
        .execute_statement_typed(
            r#"update one components with n = ? set {"$set": {"a": 1}}"#,
            &[],
        )
        .await
        .expect_err("the update document binds nothing");
    assert!(protocol_error(
        error,
        "statement expects 1 parameter(s), got 0"
    ));

    drop(server);
}

#[tokio::test]
async fn paging_rejects_delete_and_update_statements() {
    let (port, server) = spawn_server(handshake_only_server);
    let source = source_for(port).await;

    let error = source
        .query_page_start("delete components with n = 2", &[], 10)
        .await
        .expect_err("a delete has no cursor to page");
    assert!(
        protocol_error(error, "cursor paging requires a find statement"),
        "paging must reject the statement client-side"
    );

    let error = source
        .query_page_start(
            r#"update components with n = 2 set {"$set": {"a": 1}}"#,
            &[],
            10,
        )
        .await
        .expect_err("an update has no cursor to page");
    assert!(
        protocol_error(error, "cursor paging requires a find statement"),
        "paging must reject the statement client-side"
    );

    drop(server);
}
