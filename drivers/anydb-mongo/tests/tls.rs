//! TLS integration: a real rustls server behind a self-signed rcgen
//! certificate, carrying the same scripted fake mongod used in
//! `wire.rs` inside the TLS stream — the client's `ssl_mode=require`
//! wraps the transport from the very first byte (there is no mongodb
//! negotiation probe). Trust anchors come from a custom PEM root file
//! (`ssl_root_cert`) — OS stores are not touched, so tests stay
//! hermetic.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use anydb_mongo::MongoDriver;
use anydb_mongo::bson::{self, Document};
use anydb_mongo::uri::{MongoTarget, SslMode};
use anydb_mongo::wire::Connection as WireConnection;
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
    path.push(format!("anydb-mongo-tls-{}-{name}.pem", std::process::id()));
    std::fs::File::create(&path)
        .and_then(|mut file| file.write_all(pem.as_bytes()))
        .expect("write root PEM file");
    path
}

// ---------- fake mongod behind TLS ----------

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(i32, Document)> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await.ok()?;
    let length = i32::from_le_bytes(header[0..4].try_into().expect("4 bytes"));
    let request_id = i32::from_le_bytes(header[4..8].try_into().expect("4 bytes"));
    let mut body = vec![0u8; (length - 16) as usize];
    stream.read_exact(&mut body).await.ok()?;
    Some((request_id, bson::parse_document(&body[4..]).ok()?))
}

async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, response_to: i32, body: &Document) {
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
    stream.flush().await.expect("reply flush");
}

fn double_ok() -> anydb_mongo::bson::Bson {
    anydb_mongo::bson::Bson::Double(1.0)
}

/// Minimal trust flow: one-shot `hello` inside TLS announcing the TLS
/// server version; `ping` is serviced only when `expect_ping`.
async fn serve_tls(mut tls: tokio_rustls::server::TlsStream<TcpStream>, expect_ping: bool) {
    let Some((request_id, command)) = read_frame(&mut tls).await else {
        return;
    };
    assert_eq!(
        command.first().map(|(key, _)| key.as_str()),
        Some("hello"),
        "the handshake must be the first command inside TLS"
    );
    write_frame(
        &mut tls,
        request_id,
        &Document::from(vec![
            ("ok".to_owned(), double_ok()),
            (
                "version".to_owned(),
                anydb_mongo::bson::Bson::String("8.0.0-fake-tls".to_owned()),
            ),
        ]),
    )
    .await;
    if expect_ping {
        let Some((request_id, command)) = read_frame(&mut tls).await else {
            return;
        };
        assert_eq!(command.first().map(|(key, _)| key.as_str()), Some("ping"));
        write_frame(
            &mut tls,
            request_id,
            &Document::from(vec![("ok".to_owned(), double_ok())]),
        )
        .await;
    }
}

/// A plaintext listener for negative tests: accepting and dropping the
/// stream right away, so the client's TLS handshake dies on EOF/RST and
/// not on a timeout.
async fn drop_stream(stream: TcpStream) {
    drop(stream);
}

fn spawn_tls_server(expect_ping: bool) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let acceptor = TlsAcceptor::from(server_tls_config());
    let handle = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        if let Ok(tls) = acceptor.accept(stream).await {
            serve_tls(tls, expect_ping).await;
        } // untrusted chains abort the server side; nothing to do
    });
    (port, handle)
}

fn spawn_plain_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let handle = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        drop_stream(stream).await;
    });
    (port, handle)
}

fn target_for(port: u16, mode: SslMode, root_cert: Option<&PathBuf>) -> MongoTarget {
    MongoTarget {
        host: "127.0.0.1".to_owned(),
        port,
        user: None,
        password: None,
        auth_db: "admin".to_owned(),
        ssl_mode: mode,
        ssl_root_cert: root_cert.map(|path| path.to_string_lossy().into_owned()),
    }
}

fn open_request(port: u16, properties: &[(&str, &str)]) -> OpenRequest {
    OpenRequest {
        container_id: "c1".into(),
        target: format!("mongodb://127.0.0.1:{port}"),
        properties: properties
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

// ---------- tests ----------

#[tokio::test]
async fn require_mode_connects_over_tls_with_custom_root() {
    let root = write_root_file("mongo-require-ok", &test_cert().pem);
    let (port, server) = spawn_tls_server(false);
    let connection = WireConnection::connect(&target_for(port, SslMode::Require, Some(&root)))
        .await
        .expect("TLS connect");
    assert_eq!(connection.server_version(), "8.0.0-fake-tls");
    connection.terminate().await;
    server.await.expect("server task");
    std::fs::remove_file(&root).ok();
}

#[tokio::test]
async fn tls_handshake_fails_against_untrusted_chain() {
    let bad_root = write_root_file("mongo-untrusted", &foreign_cert_pem());
    let (port, server) = spawn_tls_server(false);
    let error =
        match WireConnection::connect(&target_for(port, SslMode::Require, Some(&bad_root))).await {
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
async fn require_mode_fails_against_plaintext_server() {
    let (port, server) = spawn_plain_server();
    let error = match WireConnection::connect(&target_for(port, SslMode::Require, None)).await {
        Ok(_) => panic!("require mode must fail against a plaintext-only server"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            ConnectionError::Protocol(ref message) if message.starts_with("TLS handshake failed")
        ),
        "a plaintext listener kills the handshake without answering: {error:?}"
    );
    let _ = server.await;
}

#[tokio::test]
async fn driver_passes_ssl_settings_through_open_data_source() {
    let root = write_root_file("mongo-driver", &test_cert().pem);
    let (port, server) = spawn_tls_server(true);
    let driver = MongoDriver::new();
    let source = driver
        .open_data_source(open_request(
            port,
            &[
                ("ssl_mode", "require"),
                ("ssl_root_cert", &root.to_string_lossy()),
            ],
        ))
        .await
        .expect("TLS open_data_source");
    assert_eq!(source.metadata().product_version, "8.0.0-fake-tls");
    source.ping().await.expect("ping inside TLS");
    source.close().await;
    server.await.expect("server task");
    std::fs::remove_file(&root).ok();
}

#[tokio::test]
async fn invalid_ssl_mode_fails_fast() {
    let driver = MongoDriver::new();
    // Unreachable port proves the refusal happens at resolve time.
    let error = match driver
        .open_data_source(open_request(1, &[("ssl_mode", "prefer")]))
        .await
    {
        Ok(_) => panic!("'prefer' is not a mongo ssl_mode"),
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
