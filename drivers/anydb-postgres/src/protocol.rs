//! PostgreSQL frontend protocol v3: startup, authentication exchange
//! (trust / cleartext / md5 / SCRAM-SHA-256) and the simple query protocol.
//!
//! `pub` for driver tests and advanced tooling; typical users go through
//! `PostgresDriver`.

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use anydb_shared::ConnectionError;

use crate::auth::{self, ScramClient};
use crate::url::PostgresTarget;

/// Protocol 3.0 major=3 minor=0 → 196608 (standard startup since PostgreSQL 7.4).
pub const PROTOCOL_VERSION_3: i32 = 196608;

/// One simple-query result: column names plus text-format values.
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
}

/// A live frontend connection. Single-owner by design; the data source
/// wrapper serializes access behind a tokio mutex.
pub struct Connection {
    stream: TcpStream,
    /// `ParameterStatus` values seen during startup (`server_version`, ...).
    pub server_params: HashMap<String, String>,
}

fn io_err() -> ConnectionError {
    ConnectionError::NetworkFailure
}

fn slice4(payload: &[u8]) -> Result<[u8; 4], ConnectionError> {
    payload
        .try_into()
        .map_err(|_| ConnectionError::Protocol("truncated 32-bit field".to_owned()))
}

fn slice2(payload: &[u8]) -> Result<[u8; 2], ConnectionError> {
    payload
        .try_into()
        .map_err(|_| ConnectionError::Protocol("truncated 16-bit field".to_owned()))
}

/// Reads one backend message; the length prefix (which counts itself) is
/// consumed and validated.
async fn read_message(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), ConnectionError> {
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).await.map_err(|_| io_err())?;
    let len = stream.read_i32().await.map_err(|_| io_err())?;
    if len < 4 {
        return Err(ConnectionError::Protocol(format!(
            "invalid message length {len}"
        )));
    }
    let mut payload = vec![0u8; (len - 4) as usize];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|_| io_err())?;
    Ok((tag[0], payload))
}

/// Writes one frontend message: `[tag][len][payload]`, len includes itself.
async fn write_message(
    stream: &mut TcpStream,
    tag: u8,
    payload: &[u8],
) -> Result<(), ConnectionError> {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(tag);
    frame.extend_from_slice(&(payload.len() as i32 + 4).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await.map_err(|_| io_err())?;
    stream.flush().await.map_err(|_| io_err())
}

/// Writes the startup packet (no tag byte: the only frontend message without
/// one). SSLRequest is intentionally not sent in v0 (plaintext, documented).
async fn write_startup(
    stream: &mut TcpStream,
    params: &[(&str, Option<&str>)],
) -> Result<(), ConnectionError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&PROTOCOL_VERSION_3.to_be_bytes());
    for (key, value) in params {
        let Some(value) = value else { continue };
        payload.extend_from_slice(key.as_bytes());
        payload.push(0);
        payload.extend_from_slice(value.as_bytes());
        payload.push(0);
    }
    payload.push(0);
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as i32 + 4).to_be_bytes());
    frame.extend_from_slice(&payload);
    stream.write_all(&frame).await.map_err(|_| io_err())?;
    stream.flush().await.map_err(|_| io_err())
}

/// Parses an `ErrorResponse`/`NoticeResponse` payload: repeated
/// `(u8 field-code, cstring value)` pairs, zero-terminated list.
fn parse_fields(payload: &[u8]) -> HashMap<char, String> {
    let mut fields = HashMap::new();
    let mut i = 0;
    while i < payload.len() && payload[i] != 0 {
        let code = payload[i] as char;
        i += 1;
        let start = i;
        while i < payload.len() && payload[i] != 0 {
            i += 1;
        }
        fields.insert(
            code,
            String::from_utf8_lossy(&payload[start..i]).into_owned(),
        );
        i += 1;
    }
    fields
}

fn error_response(payload: &[u8]) -> ConnectionError {
    let fields = parse_fields(payload);
    let message = fields
        .get(&'M')
        .map(String::as_str)
        .unwrap_or("unknown server error");
    match fields.get(&'S').map(String::as_str) {
        Some("FATAL") | Some("ERROR") => ConnectionError::AuthFailed,
        _ => ConnectionError::Protocol(format!("server error: {message}")),
    }
}

fn required_password(target: &PostgresTarget) -> Result<String, ConnectionError> {
    target.password.clone().ok_or(ConnectionError::AuthFailed)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

async fn handle_auth(
    stream: &mut TcpStream,
    payload: &[u8],
    target: &PostgresTarget,
    scram: &mut Option<ScramClient>,
) -> Result<(), ConnectionError> {
    if payload.len() < 4 {
        return Err(ConnectionError::Protocol(
            "truncated auth message".to_owned(),
        ));
    }
    let code = i32::from_be_bytes(slice4(&payload[0..4])?);
    match code {
        // AuthenticationOk: keep waiting for ReadyForQuery.
        0 => {}
        3 => {
            // AuthenticationCleartextPassword
            let password = required_password(target)?;
            let mut message = password.into_bytes();
            message.push(0);
            write_message(stream, b'p', &message).await?;
        }
        5 => {
            // AuthenticationMD5Password: 4-byte salt follows the code.
            let password = required_password(target)?;
            if payload.len() < 8 {
                return Err(ConnectionError::Protocol("truncated md5 salt".to_owned()));
            }
            let digest = auth::md5_password(&target.user, &password, &payload[4..8]);
            let mut message = digest.into_bytes();
            message.push(0);
            write_message(stream, b'p', &message).await?;
        }
        10 => {
            // AuthenticationSASL: mechanism list follows the code.
            let password = required_password(target)?;
            if !contains(payload, auth::SASL_MECHANISM.as_bytes()) {
                return Err(ConnectionError::Protocol(
                    "no supported SASL mechanism offered".to_owned(),
                ));
            }
            let client = ScramClient::new(&password);
            let sparse_len = client.client_first_bare().len() as i32;
            let mut message = Vec::new();
            message.extend_from_slice(auth::SASL_MECHANISM.as_bytes());
            message.push(0);
            message.extend_from_slice(&sparse_len.to_be_bytes());
            message.extend_from_slice(b"n,,");
            message.extend_from_slice(client.client_first_bare().as_bytes());
            write_message(stream, b'p', &message).await?;
            *scram = Some(client);
        }
        11 => {
            // AuthenticationSASLContinue: server-first-message data.
            let Some(client) = scram.as_mut() else {
                return Err(ConnectionError::Protocol(
                    "unexpected SASLContinue".to_owned(),
                ));
            };
            let final_message = client.client_final_message(&payload[4..])?;
            write_message(stream, b'p', final_message.as_bytes()).await?;
        }
        12 => {
            // AuthenticationSASLFinal: server-final-message data.
            let Some(client) = scram.as_ref() else {
                return Err(ConnectionError::Protocol("unexpected SASLFinal".to_owned()));
            };
            client.verify_server_final(&payload[4..])?;
        }
        other => {
            return Err(ConnectionError::Protocol(format!(
                "unsupported auth code {other}"
            )));
        }
    }
    Ok(())
}

fn apply_parameter_status(params: &mut HashMap<String, String>, payload: &[u8]) {
    let read_cstring = |start: usize| -> Option<(String, usize)> {
        let end = payload
            .get(start..)?
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| start + offset)?;
        Some((
            String::from_utf8_lossy(&payload[start..end]).into_owned(),
            end + 1,
        ))
    };
    let Some((key, next)) = read_cstring(0) else {
        return;
    };
    if let Some((value, _)) = read_cstring(next) {
        params.insert(key, value);
    }
}

/// Row description: column count, then per column `name\0` plus 18 fixed
/// bytes (table oid 4, attr 2, type oid 4, type size 2, modifier 4, format 2).
fn parse_row_description(payload: &[u8]) -> Vec<String> {
    if payload.len() < 2 {
        return Vec::new();
    }
    let count = i16::from_be_bytes([payload[0], payload[1]]);
    let mut columns = Vec::with_capacity(count.max(0) as usize);
    let mut i = 2;
    for _ in 0..count.max(0) {
        if i >= payload.len() {
            break;
        }
        let Some(end_offset) = payload[i..].iter().position(|byte| *byte == 0) else {
            break;
        };
        let end = i + end_offset;
        columns.push(String::from_utf8_lossy(&payload[i..end]).into_owned());
        // name + \0 + 18 fixed bytes; tolerate a truncated descriptor.
        i = end + 1 + 4 + 2 + 4 + 2 + 4 + 2;
        if i > payload.len() {
            break;
        }
    }
    columns
}

/// Data row: column count, then per column an i32 length (-1 = NULL) and the
/// text-format bytes.
fn parse_data_row(payload: &[u8]) -> Result<Vec<Option<String>>, ConnectionError> {
    let count = i16::from_be_bytes(slice2(&payload[0..2])?);
    let mut values = Vec::with_capacity(count.max(0) as usize);
    let mut i = 2;
    for _ in 0..count.max(0) {
        if i + 4 > payload.len() {
            return Err(ConnectionError::Protocol("truncated data row".to_owned()));
        }
        let len = i32::from_be_bytes(slice4(&payload[i..i + 4])?);
        i += 4;
        if len < 0 {
            values.push(None);
            continue;
        }
        let len = len as usize;
        if i + len > payload.len() {
            return Err(ConnectionError::Protocol("truncated data row".to_owned()));
        }
        values.push(Some(
            String::from_utf8_lossy(&payload[i..i + len]).into_owned(),
        ));
        i += len;
    }
    Ok(values)
}

impl Connection {
    /// Dials, runs the startup exchange and authenticates, returning the
    /// live connection once `ReadyForQuery` arrives.
    pub async fn connect(target: &PostgresTarget) -> Result<Self, ConnectionError> {
        let mut stream = TcpStream::connect((target.host.as_str(), target.port))
            .await
            .map_err(|_| io_err())?;

        let params: [(&str, Option<&str>); 2] = [
            ("user", Some(target.user.as_str())),
            ("database", target.database.as_deref()),
        ];
        write_startup(&mut stream, &params).await?;

        let mut scram: Option<ScramClient> = None;
        let mut server_params: HashMap<String, String> = HashMap::new();

        loop {
            let (tag, payload) = read_message(&mut stream).await?;
            match tag {
                b'R' => handle_auth(&mut stream, &payload, target, &mut scram).await?,
                b'S' => apply_parameter_status(&mut server_params, &payload),
                b'E' => return Err(error_response(&payload)),
                // BackendKeyData, NoticeResponse, NegotiateProtocolVersion.
                b'K' | b'N' | b'v' => {}
                b'Z' => {
                    return Ok(Self {
                        stream,
                        server_params,
                    });
                }
                other => {
                    return Err(ConnectionError::Protocol(format!(
                        "unexpected message {other} during startup"
                    )));
                }
            }
        }
    }

    /// Simple query protocol (`Query`). Rows are text-format strings; NULL is
    /// `None`. Returns on `ReadyForQuery`; an empty `sql` maps to the
    /// `EmptyQueryResponse` path (used as connection ping).
    pub async fn simple_query(&mut self, sql: &str) -> Result<QueryResult, ConnectionError> {
        let mut payload = sql.as_bytes().to_vec();
        payload.push(0);
        write_message(&mut self.stream, b'Q', &payload).await?;

        let mut result = QueryResult {
            columns: Vec::new(),
            rows: Vec::new(),
        };
        loop {
            let (tag, payload) = read_message(&mut self.stream).await?;
            match tag {
                b'T' => result.columns = parse_row_description(&payload),
                b'D' => result.rows.push(parse_data_row(&payload)?),
                // CommandComplete, EmptyQueryResponse, Notice, ParameterStatus.
                b'C' | b'I' | b'N' | b'S' => {}
                b'E' => return Err(error_response(&payload)),
                b'Z' => return Ok(result),
                other => {
                    return Err(ConnectionError::Protocol(format!(
                        "unexpected message {other} during query"
                    )));
                }
            }
        }
    }

    /// Sends `Terminate` and closes the TCP stream.
    pub async fn terminate(mut self) {
        let _ = write_message(&mut self.stream, b'X', &[]).await;
    }
}
