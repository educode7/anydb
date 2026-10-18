//! Wire protocol integration tests against fake PostgreSQL backends on
//! loopback. Each backend is a real server side: md5/SCRAM credentials are
//! recomputed server-side from the password, so the flows are verified
//! end-to-end without a third-party server.

use std::future::Future;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::Mac;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use anydb_postgres::PostgresDriver;
use anydb_postgres::auth::{md5_password, pbkdf2_hmac_sha256};
use anydb_postgres::protocol::PROTOCOL_VERSION_3;
use anydb_postgres::url::{PostgresTarget, SslMode};
use anydb_shared::ConnectionError;
use anydb_shared::driver::spi::{Driver, OpenRequest};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

// ---------- server side helpers ----------

async fn read_startup(stream: &mut TcpStream) -> (i32, Vec<u8>) {
    let len = stream.read_i32().await.expect("startup length");
    let mut payload = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut payload).await.expect("startup body");
    let version = i32::from_be_bytes(payload[0..4].try_into().expect("version"));
    (version, payload[4..].to_vec())
}

async fn read_frontend(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).await.expect("tag");
    let len = stream.read_i32().await.expect("length");
    let mut payload = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut payload).await.expect("body");
    (tag[0], payload)
}

async fn send(stream: &mut TcpStream, tag: u8, payload: &[u8]) {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(tag);
    frame.extend_from_slice(&(payload.len() as i32 + 4).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await.expect("write");
    stream.flush().await.expect("flush");
}

async fn authentication_ok(stream: &mut TcpStream) {
    send(stream, b'R', &0i32.to_be_bytes()).await;
}

async fn parameter_status(stream: &mut TcpStream, key: &str, value: &str) {
    send(stream, b'S', format!("{key}\0{value}\0").as_bytes()).await;
}

async fn ready_for_query(stream: &mut TcpStream) {
    send(stream, b'Z', b"I").await;
}

/// Spawns a one-shot backend on loopback and returns its address.
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

fn target_for(address: std::net::SocketAddr, password: Option<&str>) -> PostgresTarget {
    PostgresTarget {
        host: address.ip().to_string(),
        port: address.port(),
        user: "user".to_owned(),
        password: password.map(str::to_owned),
        database: Some("db".to_owned()),
        ssl_mode: SslMode::default(),
        ssl_root_cert: None,
    }
}

// ---------- server side crypto (independent of the client code) ----------

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn expected_proof(
    password: &str,
    salt: &[u8],
    iterations: u32,
    client_first_bare: &str,
    server_first: &str,
    client_final_without_proof: &str,
) -> Vec<u8> {
    let salted = pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations).expect("pbkdf2");
    let client_key = hmac(&salted, b"Client Key");
    let stored_key = sha256(&client_key);
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_without_proof
    );
    let client_signature = hmac(&stored_key, auth_message.as_bytes());
    client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

fn expected_server_signature(
    password: &str,
    salt: &[u8],
    iterations: u32,
    auth_message: &str,
) -> Vec<u8> {
    let salted = pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations).expect("pbkdf2");
    let server_key = hmac(&salted, b"Server Key");
    hmac(&server_key, auth_message.as_bytes()).to_vec()
}

// ---------- backends ----------

async fn trust_server(mut stream: TcpStream) {
    let (version, _) = read_startup(&mut stream).await;
    assert_eq!(version, PROTOCOL_VERSION_3, "startup must announce v3");
    authentication_ok(&mut stream).await;
    parameter_status(&mut stream, "server_version", "16.2").await;
    ready_for_query(&mut stream).await;
}

async fn cleartext_server(mut stream: TcpStream) {
    read_startup(&mut stream).await;
    send(&mut stream, b'R', &3i32.to_be_bytes()).await;
    let (tag, payload) = read_frontend(&mut stream).await;
    assert_eq!(tag, b'p', "cleartext flow expects a PasswordMessage");
    let sent = String::from_utf8_lossy(&payload[..payload.len() - 1]).into_owned();
    assert_eq!(sent, "secret", "server verifies the password");
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;
}

async fn md5_server(mut stream: TcpStream) {
    read_startup(&mut stream).await;
    let salt = [1u8, 2, 3, 4];
    let mut auth_request = 5i32.to_be_bytes().to_vec();
    auth_request.extend_from_slice(&salt);
    send(&mut stream, b'R', &auth_request).await;
    let (tag, payload) = read_frontend(&mut stream).await;
    assert_eq!(tag, b'p', "md5 flow expects a PasswordMessage");
    let sent = String::from_utf8_lossy(&payload[..payload.len() - 1]).into_owned();
    let expected = md5_password("user", "secret", &salt);
    assert_eq!(sent, expected, "server verifies the md5 digest");
    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;
}

async fn scram_server(mut stream: TcpStream) {
    const PASSWORD: &str = "secret";
    const ITERATIONS: u32 = 4096;
    const SALT: [u8; 8] = [7u8; 8];

    read_startup(&mut stream).await;
    let mut sasl_offer = 10i32.to_be_bytes().to_vec();
    sasl_offer.extend_from_slice(b"SCRAM-SHA-256\0");
    send(&mut stream, b'R', &sasl_offer).await;

    // SASLInitialResponse: mechanism\0, i32 length, "n,," + client-first-bare.
    let (tag, payload) = read_frontend(&mut stream).await;
    assert_eq!(tag, b'p');
    let mechanism_end = payload
        .iter()
        .position(|byte| *byte == 0)
        .expect("mechanism terminator");
    assert_eq!(&payload[..mechanism_end], b"SCRAM-SHA-256");
    let start = mechanism_end + 1 + 4;
    let bare_text = String::from_utf8_lossy(&payload[start..]).into_owned();
    let client_first_bare = bare_text
        .strip_prefix("n,,")
        .expect("SASLInitialResponse carries the GS2 header")
        .to_owned();
    let client_nonce = client_first_bare
        .strip_prefix("n=,r=")
        .expect("client-first shape");

    let salt_b64 = B64.encode(SALT);
    let server_first = format!("r={client_nonce}SRV,s={salt_b64},i={ITERATIONS}");
    let mut continue_payload = 11i32.to_be_bytes().to_vec();
    continue_payload.extend_from_slice(server_first.as_bytes());
    send(&mut stream, b'R', &continue_payload).await;

    // SASLResponse: client-final-message (no trailing zero).
    let (tag, payload) = read_frontend(&mut stream).await;
    assert_eq!(tag, b'p');
    let client_final = String::from_utf8_lossy(&payload)
        .trim_end_matches('\0')
        .to_owned();
    let (client_final_without_proof, proof_b64) =
        client_final.rsplit_once(",p=").expect("client-final shape");
    let expected = expected_proof(
        PASSWORD,
        &SALT,
        ITERATIONS,
        &client_first_bare,
        &server_first,
        client_final_without_proof,
    );
    assert_eq!(
        proof_b64,
        B64.encode(expected),
        "proof must verify server-side"
    );

    let final_nonce = client_final_without_proof
        .strip_prefix("c=biws,r=")
        .expect("final-without-proof shape");
    assert!(final_nonce.starts_with(&format!("{client_nonce}SRV")));
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_without_proof
    );
    let signature = expected_server_signature(PASSWORD, &SALT, ITERATIONS, &auth_message);
    let mut final_payload = 12i32.to_be_bytes().to_vec();
    final_payload.extend_from_slice(format!("v={}", B64.encode(signature)).as_bytes());
    send(&mut stream, b'R', &final_payload).await;

    authentication_ok(&mut stream).await;
    ready_for_query(&mut stream).await;
}

async fn error_server(mut stream: TcpStream) {
    read_startup(&mut stream).await;
    send(
        &mut stream,
        b'E',
        concat!(
            "SFATAL\0C\0",
            "28000\0M\0password authentication failed\0\0"
        )
        .as_bytes(),
    )
    .await;
}

async fn query_server(mut stream: TcpStream) {
    read_startup(&mut stream).await;
    authentication_ok(&mut stream).await;
    parameter_status(&mut stream, "server_version", "16.2").await;
    ready_for_query(&mut stream).await;

    let (tag, payload) = read_frontend(&mut stream).await;
    assert_eq!(tag, b'Q', "expect a simple Query");
    let sql = String::from_utf8_lossy(&payload[..payload.len() - 1]).into_owned();
    if sql.is_empty() {
        // Ping: EmptyQueryResponse then ReadyForQuery.
        send(&mut stream, b'I', &[]).await;
        ready_for_query(&mut stream).await;
        return;
    }
    assert_eq!(sql, "SELECT 1");

    // RowDescription: 1 column "value" + 18 fixed bytes.
    let mut description = 1i16.to_be_bytes().to_vec();
    description.extend_from_slice(b"value\0");
    description.extend_from_slice(&[0u8; 18]);
    send(&mut stream, b'T', &description).await;

    // DataRow "42".
    let mut row = 1i16.to_be_bytes().to_vec();
    row.extend_from_slice(&2i32.to_be_bytes());
    row.extend_from_slice(b"42");
    send(&mut stream, b'D', &row).await;

    // DataRow NULL.
    let mut null_row = 1i16.to_be_bytes().to_vec();
    null_row.extend_from_slice(&(-1i32).to_be_bytes());
    send(&mut stream, b'D', &null_row).await;

    send(&mut stream, b'C', b"SELECT 1\0").await;
    ready_for_query(&mut stream).await;
}

// ---------- tests ----------

#[tokio::test]
async fn connect_with_trust_auth_and_metadata() {
    let (address, server) = spawn_backend(trust_server).await;
    let target = target_for(address, None);
    let connection = anydb_postgres::protocol::Connection::connect(&target)
        .await
        .expect("trust connect");
    assert_eq!(
        connection
            .server_params
            .get("server_version")
            .map(String::as_str),
        Some("16.2")
    );
    server.await.expect("server task");
}

#[tokio::test]
async fn connect_with_cleartext_auth() {
    let (address, server) = spawn_backend(cleartext_server).await;
    let target = target_for(address, Some("secret"));
    anydb_postgres::protocol::Connection::connect(&target)
        .await
        .expect("cleartext connect");
    server.await.expect("server task");
}

#[tokio::test]
async fn connect_with_md5_auth() {
    let (address, server) = spawn_backend(md5_server).await;
    let target = target_for(address, Some("secret"));
    anydb_postgres::protocol::Connection::connect(&target)
        .await
        .expect("md5 connect");
    server.await.expect("server task");
}

#[tokio::test]
async fn connect_with_scram_sha_256() {
    let (address, server) = spawn_backend(scram_server).await;
    let target = target_for(address, Some("secret"));
    anydb_postgres::protocol::Connection::connect(&target)
        .await
        .expect("scram connect");
    server.await.expect("server task");
}

#[tokio::test]
async fn error_response_maps_to_auth_failed() {
    let (address, server) = spawn_backend(error_server).await;
    let target = target_for(address, Some("secret"));
    let error = match anydb_postgres::protocol::Connection::connect(&target).await {
        Ok(_) => panic!("connect must fail against an ErrorResponse"),
        Err(error) => error,
    };
    assert_eq!(error, ConnectionError::AuthFailed);
    let _ = server.await;
}

#[tokio::test]
async fn simple_query_parses_rows_and_nulls() {
    let (address, server) = spawn_backend(query_server).await;
    let mut connection = anydb_postgres::protocol::Connection::connect(&target_for(address, None))
        .await
        .expect("connect");
    let result = connection
        .simple_query("SELECT 1")
        .await
        .expect("query result");
    assert_eq!(result.columns, vec!["value"]);
    assert_eq!(result.rows, vec![vec![Some("42".to_owned())], vec![None]]);
    server.await.expect("server task");
}

#[tokio::test]
async fn driver_connects_pings_and_closes_via_wire() {
    let (address, server) = spawn_backend(query_server).await;
    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "c1".into(),
        target: format!("postgres://user:secret@{}/db", address),
        properties: Default::default(),
    };
    let source = driver
        .open_data_source(request)
        .await
        .expect("live open_data_source");
    assert_eq!(source.metadata().product_version, "16.2");
    source.ping().await.expect("ping over the wire");
    source.close().await;
    server.await.expect("server task");
}

#[tokio::test]
async fn wire_data_source_executes_simple_queries() {
    let (address, server) = spawn_backend(query_server).await;
    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "c1".into(),
        target: format!("postgres://user:secret@{}/db", address),
        properties: Default::default(),
    };
    let wire = driver.open_wire_data_source(request).await.expect("open");
    let result = wire.simple_query("SELECT 1").await.expect("query");
    assert_eq!(result.rows, vec![vec![Some("42".to_owned())], vec![None]]);
    server.await.expect("server task");
}

#[tokio::test]
async fn properties_override_url_credentials() {
    // The URL carries no credentials; the resolved settings provide the user
    // (secrets pipeline output). Reaching the server's error response proves
    // the override made it into the startup packet.
    let (address, server) = spawn_backend(|mut stream| async move {
        let (_, body) = read_startup(&mut stream).await;
        let text = String::from_utf8_lossy(&body).into_owned();
        assert!(
            text.contains("user\0user\0"),
            "startup must carry the settings user: {text}"
        );
        send(&mut stream, b'E', b"SFATAL\0M\0bad credentials\0\0").await;
    })
    .await;
    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "c1".into(),
        target: format!("postgres://{}/db", address),
        properties: [("user".to_owned(), "user".to_owned())]
            .into_iter()
            .collect(),
    };
    let error = match driver.open_data_source(request).await {
        Ok(_) => panic!("must fail against the error response"),
        Err(error) => error,
    };
    assert_eq!(error, ConnectionError::AuthFailed);
    let _ = server.await;
}
