//! Wire tests against a scripted fake mongod: real loopback TCP, real
//! OP_MSG frames, and a SERVER side that genuinely computes SCRAM
//! (verifies the client proof against a known password and signs the
//! server-final message with RustCrypto directly — the client side of
//! `scram.rs` is never trusted).

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::task::JoinSet;

use anydb_mongo::WireDataSource;
use anydb_mongo::bson::{self, Bson, Document};
use anydb_mongo::uri::parse_target;
use anydb_shared::ConnectionError;
use anydb_shared::driver::spi::DataSource;
use anydb_shared::driver::statement::{QueryParameter, TypedValue};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

const PASSWORD: &str = "s3cret";
const SALT_B64: &str = "c2FsdHNhbHRzYWx0";
const ITERATIONS: u32 = 4096;
const SERVER_NONCE_SUFFIX: &str = "srv6810";

#[derive(Default, Clone, Copy)]
struct Scenario {
    /// `None` = legacy server that does not advertise a mechanism list.
    mechanisms: Option<&'static [&'static str]>,
    /// The server rejects the final proof with mongo code 18.
    bad_password: bool,
    /// The server-final signature is garbage the client must catch.
    corrupt_server_final: bool,
    /// `find` reply cursor id (0 = closed, non-zero = protocol error).
    cursor_id: i64,
}

// ---------- server-side crypto (RustCrypto, independent of the driver) ----------

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("key");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("key");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    server_pbkdf2(hmac_sha1, 20, password, salt, iterations)
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    server_pbkdf2(hmac_sha256, 32, password, salt, iterations)
}

fn server_pbkdf2(
    hmac: fn(&[u8], &[u8]) -> Vec<u8>,
    output: usize,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Vec<u8> {
    let mut previous = hmac(password, &[salt, &1u32.to_be_bytes()].concat());
    let mut out = previous.clone();
    for _round in 2..=iterations {
        previous = hmac(password, &previous);
        for (slot, chunk) in out.iter_mut().zip(previous.iter()) {
            *slot ^= chunk;
        }
    }
    out.truncate(output);
    out
}

type HmacFn = fn(&[u8], &[u8]) -> Vec<u8>;
type DigestFn = fn(&[u8]) -> Vec<u8>;

/// Server-side proof verification; returns the server signature bytes
/// when the proof is right (`None` when the client cheated).
fn verify_client_proof(
    mechanism: &str,
    client_final: &str,
    bare_intro: &str,
    password: &str,
) -> Option<Vec<u8>> {
    let proof_position = client_final.find(",p=")?;
    let without_proof = &client_final[..proof_position];
    let received = BASE64.decode(&client_final[proof_position + 3..]).ok()?;
    // Proof-free part must be the bind data plus the combined nonce.
    without_proof.strip_prefix("c=biws,r=")?;
    let salt = BASE64.decode(SALT_B64).expect("salt");
    let salted = match mechanism {
        "SCRAM-SHA-256" => pbkdf2_sha256(password.as_bytes(), &salt, ITERATIONS),
        "SCRAM-SHA-1" => pbkdf2_sha1(password.as_bytes(), &salt, ITERATIONS),
        _ => return None,
    };
    let (hmac, digest): (HmacFn, DigestFn) = match mechanism {
        "SCRAM-SHA-256" => (
            hmac_sha256 as HmacFn,
            (|data| Sha256::digest(data).to_vec()) as DigestFn,
        ),
        _ => (
            hmac_sha1 as HmacFn,
            (|data| Sha1::digest(data).to_vec()) as DigestFn,
        ),
    };
    let client_key = hmac(&salted, b"Client Key");
    let stored_key = digest(&client_key);
    let client_signature = hmac(&stored_key, without_proof.as_bytes());
    let expected: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(key, signature)| key ^ signature)
        .collect();
    if received != expected {
        return None;
    }
    let server_key = hmac(&salted, b"Server Key");
    // RFC 5802: ServerSignature = HMAC(ServerKey, AuthMessage), the
    // auth message being client-first-BARE , client-final-without-proof.
    let auth_message = format!("{bare_intro},{without_proof}");
    Some(hmac(&server_key, auth_message.as_bytes()))
}

// ---------- wire helpers on the fake server ----------

fn int32(value: i32) -> Bson {
    Bson::Int32(value)
}

fn double_ok() -> Bson {
    Bson::Double(1.0)
}

fn batch_array() -> Bson {
    Bson::Array(vec![
        Bson::Document(Document::from(vec![
            ("n".to_owned(), int32(1)),
            ("tag".to_owned(), Bson::String("a".to_owned())),
        ])),
        Bson::Document(Document::from(vec![
            ("n".to_owned(), Bson::Int64(2)),
            ("flag".to_owned(), Bson::Boolean(true)),
            ("blob".to_owned(), Bson::Binary(vec![0xCA, 0xFE])),
            (
                "oid".to_owned(),
                Bson::ObjectId([
                    0x64u8, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
                ]),
            ),
            ("at".to_owned(), Bson::DateTime(1_700_000_000_000)),
        ])),
    ])
}

async fn read_frame(stream: &mut OwnedReadHalf) -> Option<(i32, Document)> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await.ok()?;
    let length = i32::from_le_bytes(header[0..4].try_into().expect("4 bytes"));
    let request_id = i32::from_le_bytes(header[4..8].try_into().expect("4 bytes"));
    let mut body = vec![0u8; (length - 16) as usize];
    stream.read_exact(&mut body).await.ok()?;
    Some((request_id, bson::parse_document(&body[4..]).ok()?))
}

async fn write_frame(stream: &mut OwnedWriteHalf, response_to: i32, body: &Document) {
    let document = bson::encode_document(body).expect("reply encodes");
    let length = (20 + document.len()) as i32;
    let mut out = Vec::with_capacity(length as usize);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&2i32.to_le_bytes());
    out.extend_from_slice(&response_to.to_le_bytes());
    out.extend_from_slice(&2013i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&document);
    stream.write_all(&out).await.expect("reply write");
}

/// One fake mongod over one connection.
async fn serve(
    mut read: OwnedReadHalf,
    mut write: OwnedWriteHalf,
    scenario: Scenario,
    log: Arc<StdMutex<Vec<String>>>,
) {
    let mut mechanism: Option<String> = None;
    let mut bare_intro = String::new();
    let mut conversation_id = 0;
    loop {
        let Some((request_id, command)) = read_frame(&mut read).await else {
            return;
        };
        let Some((key, _)) = command.first() else {
            return;
        };
        match key.as_str() {
            "hello" => {
                log.lock().expect("log").push("hello".to_owned());
                let mut reply = Document::from(vec![
                    ("ok".to_owned(), double_ok()),
                    ("version".to_owned(), Bson::String("8.0.0-fake".to_owned())),
                ]);
                if let Some(mechanisms) = scenario.mechanisms {
                    reply.push((
                        "saslSupportedMechs".to_owned(),
                        Bson::Array(
                            mechanisms
                                .iter()
                                .map(|name| Bson::String((*name).to_owned()))
                                .collect(),
                        ),
                    ));
                }
                write_frame(&mut write, request_id, &reply).await;
            }
            "saslStart" => {
                let Bson::String(name) = command
                    .iter()
                    .find(|(field, _)| field == "mechanism")
                    .map(|(_, value)| value)
                    .expect("mechanism")
                else {
                    panic!("saslStart mechanism is not a string");
                };
                mechanism = Some(name.clone());
                log.lock().expect("log").push(format!("saslStart:{name}"));
                let Bson::Binary(payload) = command
                    .iter()
                    .find(|(field, _)| field == "payload")
                    .map(|(_, value)| value)
                    .expect("payload")
                else {
                    panic!("saslStart payload is not binary");
                };
                let client_first = std::str::from_utf8(payload).expect("utf8 payload");
                assert!(
                    client_first.starts_with("n,,n="),
                    "mongo saslStart carries the full client-first message"
                );
                let client_nonce = client_first["n,,".len()..]
                    .split_once(",r=")
                    .expect("client nonce")
                    .1
                    .to_owned();
                bare_intro = client_first["n,,".len()..].to_owned();
                let server_nonce = format!("{client_nonce}{SERVER_NONCE_SUFFIX}");
                conversation_id = 1;
                let server_first = format!("r={server_nonce},s={},i={ITERATIONS}", SALT_B64);
                let reply = Document::from(vec![
                    ("ok".to_owned(), int32(1)),
                    ("conversationId".to_owned(), int32(1)),
                    ("done".to_owned(), Bson::Boolean(false)),
                    (
                        "payload".to_owned(),
                        Bson::Binary(server_first.into_bytes()),
                    ),
                ]);
                write_frame(&mut write, request_id, &reply).await;
            }
            "saslContinue" => {
                log.lock().expect("log").push("saslContinue".to_owned());
                let Bson::Binary(payload) = command
                    .iter()
                    .find(|(field, _)| field == "payload")
                    .map(|(_, value)| value)
                    .expect("payload")
                else {
                    panic!("saslContinue payload is not binary");
                };
                let client_final = std::str::from_utf8(payload).expect("utf8 payload");
                let signature = verify_client_proof(
                    mechanism.as_deref().expect("mechanism"),
                    client_final,
                    &bare_intro,
                    PASSWORD,
                );
                if bad_proof(&scenario, &signature) {
                    let reply = Document::from(vec![
                        ("ok".to_owned(), Bson::Double(0.0)),
                        ("code".to_owned(), int32(18)),
                        (
                            "errmsg".to_owned(),
                            Bson::String("Authentication failed.".to_owned()),
                        ),
                    ]);
                    write_frame(&mut write, request_id, &reply).await;
                    continue;
                }
                let plain_four_bytes = [SERVER_NONCE_SUFFIX.len() as u8, 0x00, 0x00, 0x00];
                let value = if scenario.corrupt_server_final {
                    format!("v={}", BASE64.encode(plain_four_bytes))
                } else {
                    format!("v={}", BASE64.encode(signature.expect("verified proof")))
                };
                let reply = Document::from(vec![
                    ("ok".to_owned(), int32(1)),
                    ("conversationId".to_owned(), int32(conversation_id)),
                    ("done".to_owned(), Bson::Boolean(true)),
                    ("payload".to_owned(), Bson::Binary(value.into_bytes())),
                ]);
                write_frame(&mut write, request_id, &reply).await;
            }
            "find" => {
                log.lock().expect("log").push("find".to_owned());
                assert!(
                    command
                        .iter()
                        .any(|(field, value)| field == "singleBatch"
                            && *value == Bson::Boolean(true)),
                    "one-shot find must close the cursor"
                );
                let reply = Document::from(vec![
                    ("ok".to_owned(), int32(1)),
                    (
                        "cursor".to_owned(),
                        Bson::Document(Document::from(vec![
                            ("id".to_owned(), Bson::Int64(scenario.cursor_id)),
                            ("ns".to_owned(), Bson::String("authdb.c1".to_owned())),
                            ("firstBatch".to_owned(), batch_array()),
                        ])),
                    ),
                ]);
                write_frame(&mut write, request_id, &reply).await;
            }
            "ping" => {
                log.lock().expect("log").push("ping".to_owned());
                let reply = Document::from(vec![("ok".to_owned(), double_ok())]);
                write_frame(&mut write, request_id, &reply).await;
            }
            unexpected => {
                log.lock()
                    .expect("log")
                    .push(format!("unexpected:{unexpected}"));
                let reply = Document::from(vec![
                    ("ok".to_owned(), Bson::Double(0.0)),
                    ("code".to_owned(), int32(59)),
                    (
                        "errmsg".to_owned(),
                        Bson::String("command not handled".to_owned()),
                    ),
                ]);
                write_frame(&mut write, request_id, &reply).await;
            }
        }
    }
}

fn bad_proof(scenario: &Scenario, signature: &Option<Vec<u8>>) -> bool {
    scenario.bad_password || signature.is_none()
}

fn spawn_server(scenario: Scenario) -> (u16, Arc<StdMutex<Vec<String>>>, JoinSet<()>) {
    let (port, listener) = spawn_listener();
    let log = Arc::new(StdMutex::new(Vec::new()));
    let mut tasks = JoinSet::new();
    tasks.spawn(accept_one(listener, scenario, log.clone()));
    (port, log, tasks)
}

fn spawn_listener() -> (u16, TcpListener) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    // Spawned back through tokio.
    listener.set_nonblocking(true).expect("nonblocking");
    let listener = TcpListener::from_std(listener).expect("tokio listener");
    (port, listener)
}

async fn accept_one(listener: TcpListener, scenario: Scenario, log: Arc<StdMutex<Vec<String>>>) {
    let Ok((stream, _)) = listener.accept().await else {
        return;
    };
    let (read, write) = stream.into_split();
    serve(read, write, scenario, log).await;
}

async fn source_for(
    port: u16,
    url_suffix: &str,
    properties: &[(&str, &str)],
) -> Arc<WireDataSource> {
    let url = format!("mongodb://{url_suffix}{port}");
    let mut target = parse_target(&url, None).expect("target parses");
    for (key, value) in properties {
        match *key {
            "user" => target.user = Some((*value).to_owned()),
            "password" => target.password = Some((*value).to_owned()),
            "auth_source" => target.auth_db = (*value).to_owned(),
            unexpected => panic!("unexpected override key {unexpected}"),
        }
    }
    WireDataSource::open(&target).await.expect("open")
}

#[tokio::test]
async fn connects_authenticates_finds_and_pings_with_typed_mapping() {
    let (port, log, mut server) = spawn_server(Scenario {
        mechanisms: Some(&["SCRAM-SHA-256"]),
        ..Scenario::default()
    });
    let source = source_for(
        port,
        "scram:s3cret@127.0.0.1:",
        &[("auth_source", "authdb")],
    )
    .await;
    assert_eq!(source.metadata().product_name, "MongoDB");
    assert_eq!(source.metadata().product_version, "8.0.0-fake");

    let typed = source
        .execute_statement_typed("find c1", &[])
        .await
        .expect("find works");
    assert_eq!(typed.columns, vec!["n", "tag", "flag", "blob", "oid", "at"]);
    assert_eq!(
        typed.rows,
        vec![
            vec![
                Some(TypedValue::Int4(1)),
                Some(TypedValue::Text("a".to_owned())),
                None,
                None,
                None,
                None,
            ],
            vec![
                Some(TypedValue::Int8(2)),
                None,
                Some(TypedValue::Boolean(true)),
                Some(TypedValue::Bytea(vec![0xCA, 0xFE])),
                Some(TypedValue::Text("6465666768696a6b6c6d6e6f".to_owned())),
                Some(TypedValue::Text("2023-11-14T22:13:20.000Z".to_owned())),
            ],
        ]
    );
    assert_eq!(typed.command_tag.as_deref(), Some("find 2"));
    assert_eq!(typed.affected_rows, Some(2));

    source.ping().await.expect("ping works");

    let untyped = source
        .execute_statement("find c1", &[])
        .await
        .expect("find works");
    assert_eq!(untyped.columns, typed.columns);
    assert_eq!(
        untyped.rows[0],
        vec![
            Some("1".to_owned()),
            Some("a".to_owned()),
            None,
            None,
            None,
            None
        ]
    );

    assert_eq!(
        *log.lock().expect("log"),
        vec![
            "hello".to_owned(),
            "saslStart:SCRAM-SHA-256".to_owned(),
            "saslContinue".to_owned(),
            "find".to_owned(),
            "ping".to_owned(),
            "find".to_owned(),
        ],
        "the untyped surface re-runs find through the typed core"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn legacy_servers_default_to_sha256_when_no_mechanisms_are_listed() {
    let (port, log, mut server) = spawn_server(Scenario::default());
    source_for(
        port,
        "scram:s3cret@127.0.0.1:",
        &[("auth_source", "authdb")],
    )
    .await
    .execute_statement_typed("find c1", &[])
    .await
    .expect("find works");
    assert_eq!(
        *log.lock().expect("log"),
        vec![
            "hello".to_owned(),
            "saslStart:SCRAM-SHA-256".to_owned(),
            "saslContinue".to_owned(),
            "find".to_owned(),
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn sha1_mechanism_negotiates_when_it_is_the_only_option() {
    let (port, log, mut server) = spawn_server(Scenario {
        mechanisms: Some(&["SCRAM-SHA-1"]),
        ..Scenario::default()
    });
    source_for(
        port,
        "scram:s3cret@127.0.0.1:",
        &[("auth_source", "authdb")],
    )
    .await
    .execute_statement_typed("find c1", &[])
    .await
    .expect("find works");
    assert_eq!(
        *log.lock().expect("log"),
        vec![
            "hello".to_owned(),
            "saslStart:SCRAM-SHA-1".to_owned(),
            "saslContinue".to_owned(),
            "find".to_owned(),
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn mongo_code_18_maps_to_auth_failed() {
    let (port, _log, mut server) = spawn_server(Scenario {
        bad_password: true,
        ..Scenario::default()
    });
    let mut target = parse_target("mongodb://scram:s3cret@127.0.0.1", None).expect("target");
    target.port = port;
    let error = WireDataSource::open(&target)
        .await
        .expect_err("auth must fail");
    assert_eq!(error, ConnectionError::AuthFailed);
    server.shutdown().await;
}

#[tokio::test]
async fn corrupted_server_final_fails_the_handshake() {
    let (port, _log, mut server) = spawn_server(Scenario {
        corrupt_server_final: true,
        ..Scenario::default()
    });
    let mut target = parse_target("mongodb://scram:s3cret@127.0.0.1", None).expect("target");
    target.port = port;
    let error = WireDataSource::open(&target)
        .await
        .expect_err("signature must fail");
    assert_eq!(error, ConnectionError::AuthFailed);
    server.shutdown().await;
}

#[tokio::test]
async fn server_with_no_standard_mechanism_is_an_auth_failure() {
    let (port, _log, mut server) = spawn_server(Scenario {
        mechanisms: Some(&["PLAIN"]),
        ..Scenario::default()
    });
    let mut target = parse_target("mongodb://scram:s3cret@127.0.0.1", None).expect("target");
    target.port = port;
    let error = WireDataSource::open(&target)
        .await
        .expect_err("no SCRAM offered");
    assert_eq!(error, ConnectionError::AuthFailed);
    server.shutdown().await;
}

#[tokio::test]
async fn anonymous_connect_skips_sasl_altogether() {
    let (port, log, mut server) = spawn_server(Scenario::default());
    let source = source_for(port, "127.0.0.1:", &[]).await;
    source
        .execute_statement_typed("find c1", &[])
        .await
        .expect("find works");
    assert_eq!(
        *log.lock().expect("log"),
        vec!["hello".to_owned(), "find".to_owned(),]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn open_cursor_replies_are_protocol_errors() {
    let (port, _log, mut server) = spawn_server(Scenario {
        cursor_id: 1234,
        ..Scenario::default()
    });
    let source = source_for(port, "127.0.0.1:", &[]).await;
    let error = source
        .execute_statement_typed("find c1", &[])
        .await
        .expect_err("open cursor refused");
    assert!(matches!(
        error,
        ConnectionError::Protocol(message) if message.contains("open cursor")
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn statement_forms_beyond_find_and_params_are_rejected() {
    let (port, _log, mut server) = spawn_server(Scenario::default());
    let source = source_for(port, "127.0.0.1:", &[]).await;
    let error = source
        .execute_statement_typed("drop db", &[])
        .await
        .expect_err("unsupported statement");
    assert!(
        matches!(error, ConnectionError::Protocol(message) if message.contains("unsupported statement"))
    );
    let error = source
        .execute_statement_typed("find c1", &[QueryParameter::Text("x".to_owned())])
        .await
        .expect_err("params refused");
    assert!(
        matches!(error, ConnectionError::Protocol(message) if message.contains("take no parameters"))
    );
    server.shutdown().await;
}

#[tokio::test]
async fn user_without_password_fails_before_scram() {
    let (port, _log, mut server) = spawn_server(Scenario::default());
    let mut target = parse_target("mongodb://scram@127.0.0.1", None).expect("target");
    target.port = port;
    let error = WireDataSource::open(&target)
        .await
        .expect_err("no password");
    assert!(matches!(error, ConnectionError::Protocol(message) if message.contains("password")));
    server.shutdown().await;
}
