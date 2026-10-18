//! TLS integration: a real rustls server behind a self-signed rcgen
//! certificate, exercising the client's `ssl_mode` levels end-to-end
//! (SSLRequest, TLS handshake, startup exchange inside TLS). Trust anchors
//! come from a custom PEM root file (`ssl_root_cert`) — OS stores are not
//! touched, so tests stay hermetic.

use std::future::Future;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use anydb_postgres::PostgresDriver;
use anydb_postgres::protocol::{Connection as WireConnection, SSL_REQUEST_CODE};
use anydb_postgres::url::{PostgresTarget, SslMode};
use anydb_shared::ConnectionError;
use anydb_shared::driver::spi::{Driver, OpenRequest};

// ---------- certificate material (generated once per test binary) ----------

struct TestCert {
    /// Server certificate DER plus the matching PKCS#8 key DER.
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    /// PEM form of the certificate, used as the client trust anchor file.
    pem: String,
}

fn test_cert() -> &'static TestCert {
    static CERT: OnceLock<TestCert> = OnceLock::new();
    CERT.get_or_init(|| {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("generate key pair (ring)");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("certificate parameters");
        let cert = params.self_signed(&key).expect("self-signed certificate");
        TestCert {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
            pem: cert.pem(),
        }
    })
}

/// A second, unrelated self-signed cert for negative trust tests.
fn foreign_cert_pem() -> String {
    static FOREIGN: OnceLock<String> = OnceLock::new();
    FOREIGN
        .get_or_init(|| {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .expect("generate key pair (ring)");
            let params = rcgen::CertificateParams::new(vec!["other.local".to_string()])
                .expect("certificate parameters");
            params
                .self_signed(&key)
                .expect("self-signed certificate")
                .pem()
        })
        .clone()
}

fn server_tls_config() -> Arc<ServerConfig> {
    let cert = test_cert();
    let config =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_der.clone())),
            )
            .expect("valid server TLS config");
    Arc::new(config)
}

fn write_root_file(name: &str, pem: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("anydb-tls-{}-{name}.pem", std::process::id()));
    std::fs::File::create(&path)
        .and_then(|mut file| file.write_all(pem.as_bytes()))
        .expect("write root PEM file");
    path
}

// ---------- server side helpers (transport-generic) ----------

async fn read_startup<S: AsyncRead + std::marker::Unpin>(stream: &mut S) -> (i32, Vec<u8>) {
    let len = stream.read_i32().await.expect("startup length");
    let mut payload = vec![0u8; (len - 4) as usize];
    stream.read_exact(&mut payload).await.expect("startup body");
    let version = i32::from_be_bytes(payload[0..4].try_into().expect("version"));
    (version, payload[4..].to_vec())
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

async fn parameter_status<S: AsyncWrite + std::marker::Unpin>(
    stream: &mut S,
    key: &str,
    value: &str,
) {
    send(stream, b'S', format!("{key}\0{value}\0").as_bytes()).await;
}

async fn ready_for_query<S: AsyncWrite + std::marker::Unpin>(stream: &mut S) {
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

/// Answers SSLRequest with 'S', upgrades to TLS, then runs the trust flow.
/// With `expect_ping` it services the empty Query (ping) before ending.
async fn tls_trust_server(mut stream: TcpStream, expect_ping: bool) {
    let mut ssl_request = [0u8; 8];
    stream
        .read_exact(&mut ssl_request)
        .await
        .expect("ssl request");
    assert_eq!(&ssl_request[0..4], &8i32.to_be_bytes(), "SSLRequest len");
    assert_eq!(
        &ssl_request[4..8],
        &SSL_REQUEST_CODE.to_be_bytes(),
        "SSLRequest code"
    );
    stream.write_all(b"S").await.expect("ssl answer");
    stream.flush().await.expect("ssl flush");

    let acceptor = TlsAcceptor::from(server_tls_config());
    let mut tls = acceptor.accept(stream).await.expect("server TLS accept");

    let (version, _) = read_startup(&mut tls).await;
    assert_eq!(
        version,
        anydb_postgres::protocol::PROTOCOL_VERSION_3,
        "startup must arrive inside TLS"
    );
    authentication_ok(&mut tls).await;
    parameter_status(&mut tls, "server_version", "16.2-tls").await;
    ready_for_query(&mut tls).await;

    if expect_ping {
        // Ping: empty simple query inside TLS.
        let (tag, payload) = read_message(&mut tls).await;
        assert_eq!(tag, b'Q', "expect the ping as an empty Query");
        let sql = String::from_utf8_lossy(&payload[..payload.len() - 1]).into_owned();
        assert!(sql.is_empty(), "ping must be the empty query, got {sql:?}");
        send(&mut tls, b'I', &[]).await;
        ready_for_query(&mut tls).await;
    }
}

/// Answers SSLRequest with 'N' and continues in plaintext (trust flow).
async fn no_ssl_trust_server(mut stream: TcpStream) {
    let mut ssl_request = [0u8; 8];
    stream
        .read_exact(&mut ssl_request)
        .await
        .expect("ssl request");
    assert_eq!(&ssl_request[4..8], &SSL_REQUEST_CODE.to_be_bytes());
    stream.write_all(b"N").await.expect("ssl answer");

    let (version, _) = read_startup(&mut stream).await;
    assert_eq!(version, anydb_postgres::protocol::PROTOCOL_VERSION_3);
    authentication_ok(&mut stream).await;
    parameter_status(&mut stream, "server_version", "16.2-plain").await;
    ready_for_query(&mut stream).await;
}

// ---------- tests ----------

fn target_with(
    address: std::net::SocketAddr,
    mode: SslMode,
    root_cert: Option<&PathBuf>,
) -> PostgresTarget {
    PostgresTarget {
        host: address.ip().to_string(),
        port: address.port(),
        user: "user".to_owned(),
        password: None,
        database: Some("db".to_owned()),
        ssl_mode: mode,
        ssl_root_cert: root_cert.map(|path| path.to_string_lossy().into_owned()),
    }
}

#[tokio::test]
async fn require_mode_connects_over_tls_with_custom_root() {
    let root = write_root_file("require-ok", &test_cert().pem);
    let (address, server) = spawn_backend(|stream| tls_trust_server(stream, false)).await;
    let connection = WireConnection::connect(&target_with(address, SslMode::Require, Some(&root)))
        .await
        .expect("TLS connect");
    assert_eq!(
        connection
            .server_params
            .get("server_version")
            .map(String::as_str),
        Some("16.2-tls")
    );
    server.await.expect("server task");
    std::fs::remove_file(&root).ok();
}

#[tokio::test]
async fn prefer_mode_falls_back_to_plaintext() {
    let (address, server) = spawn_backend(no_ssl_trust_server).await;
    let connection = WireConnection::connect(&target_with(address, SslMode::Prefer, None))
        .await
        .expect("plaintext fallback");
    assert_eq!(
        connection
            .server_params
            .get("server_version")
            .map(String::as_str),
        Some("16.2-plain")
    );
    server.await.expect("server task");
}

#[tokio::test]
async fn require_mode_fails_when_server_rejects_ssl() {
    let (address, server) = spawn_backend(no_ssl_trust_server).await;
    let error = match WireConnection::connect(&target_with(address, SslMode::Require, None)).await {
        Ok(_) => panic!("require mode must fail against a plaintext-only server"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        ConnectionError::Protocol("server does not support SSL (ssl_mode=require)".to_owned())
    );
    let _ = server.await;
}

#[tokio::test]
async fn tls_handshake_fails_against_untrusted_chain() {
    let bad_root = write_root_file("untrusted", &foreign_cert_pem());
    let (address, server) = spawn_backend(|stream| tls_trust_server(stream, false)).await;
    let error =
        match WireConnection::connect(&target_with(address, SslMode::Require, Some(&bad_root)))
            .await
        {
            Ok(_) => panic!("untrusted chain must fail the handshake"),
            Err(error) => error,
        };
    assert!(
        matches!(
            error,
            ConnectionError::Protocol(ref message) if message.starts_with("TLS handshake failed")
        ),
        "unexpected error: {error:?}"
    );
    let _ = server.await;
    std::fs::remove_file(&bad_root).ok();
}

#[tokio::test]
async fn driver_passes_ssl_settings_through_open_data_source() {
    let root = write_root_file("driver", &test_cert().pem);
    let (address, server) = spawn_backend(|stream| tls_trust_server(stream, true)).await;
    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "c1".into(),
        target: format!("postgres://user@{}/db", address),
        properties: [
            ("ssl_mode".to_owned(), "require".to_owned()),
            (
                "ssl_root_cert".to_owned(),
                root.to_string_lossy().into_owned(),
            ),
        ]
        .into_iter()
        .collect(),
    };
    let source = driver
        .open_data_source(request)
        .await
        .expect("TLS open_data_source");
    assert_eq!(source.metadata().product_version, "16.2-tls");
    source.ping().await.expect("ping inside TLS");
    source.close().await;
    server.await.expect("server task");
    std::fs::remove_file(&root).ok();
}

#[tokio::test]
async fn invalid_ssl_mode_fails_fast() {
    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "c1".into(),
        target: "postgres://user@example.invalid/db".into(),
        properties: [("ssl_mode".to_owned(), "bogus".to_owned())]
            .into_iter()
            .collect(),
    };
    let error = match driver.open_data_source(request).await {
        Ok(_) => panic!("invalid ssl_mode must fail before dialing"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            ConnectionError::Protocol(ref message) if message.contains("invalid ssl_mode")
        ),
        "unexpected error: {error:?}"
    );
}
