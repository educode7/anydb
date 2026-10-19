//! Mongo wire client over OP_MSG: `hello` handshake (_learned_
//! `saslSupportedMechs`), SCRAM authentication, one-shot `find` and
//! `ping`. One `Connection` drives exactly one TCP stream; concurrency
//! is serialized one level up (the driver facade's tokio mutex), so all
//! methods take `&mut self`.
//!
//! Deliberate scope: plaintext TCP only (TLS is future wire work), and
//! cursors are single-batch (`singleBatch: true`) — batch resumption is
//! the paging vertical, not this layer.

use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use crate::bson::{Bson, Document};
use crate::op_msg::OpMsg;
use crate::scram::{Mechanism, ScramClient};
use crate::uri::MongoTarget;
use anydb_shared::ConnectionError;

fn protocol(message: String) -> ConnectionError {
    ConnectionError::Protocol(format!("mongo wire: {message}"))
}

fn int32_field(document: &Document, key: &str) -> i32 {
    match document.iter().find(|(field_key, _)| field_key == key) {
        Some((_, Bson::Int32(value))) => *value,
        Some((_, Bson::Int64(value))) => *value as i32,
        _ => 0,
    }
}

#[derive(Debug)]
pub struct Connection {
    stream: TcpStream,
    next_request_id: i32,
    server_version: String,
}

impl Connection {
    /// TCP connect + `hello` handshake + optional SCRAM. A URL without
    /// credentials connects anonymously (SCRAM is skipped entirely).
    pub async fn connect(target: &MongoTarget) -> Result<Self, ConnectionError> {
        let stream = TcpStream::connect((target.host.as_str(), target.port))
            .await
            .map_err(|_| ConnectionError::NetworkFailure)?;
        let mut connection = Self {
            stream,
            next_request_id: 1,
            server_version: "unknown".to_owned(),
        };

        let mut handshake = Document::from(vec![
            ("hello".to_owned(), Bson::Int32(1)),
            (
                "client".to_owned(),
                Bson::Document(Document::from(vec![
                    (
                        "driver".to_owned(),
                        Bson::Document(Document::from(vec![
                            ("name".to_owned(), Bson::String("anydb-mongo".to_owned())),
                            (
                                "version".to_owned(),
                                Bson::String(env!("CARGO_PKG_VERSION").to_owned()),
                            ),
                        ])),
                    ),
                    ("os".to_owned(), Bson::Document(Document::new())),
                    (
                        "platform".to_owned(),
                        Bson::String(env!("CARGO_PKG_VERSION").to_owned()),
                    ),
                ])),
            ),
        ]);
        if let Some(user) = &target.user {
            handshake.push((
                "saslSupportedMechs".to_owned(),
                Bson::String(format!("{}.{}", target.auth_db, user)),
            ));
        }
        let reply = connection.command(&handshake).await?;
        if let Some((_, Bson::String(version))) = reply.iter().find(|(key, _)| key == "version") {
            connection.server_version = version.clone();
        }

        if let Some(user) = &target.user {
            let Some(password) = &target.password else {
                return Err(protocol(
                    "SCRAM needs a password (URL or properties) for the target user".to_owned(),
                ));
            };
            let offered = offered_mechanisms(&reply);
            let mechanism = Mechanism::negotiate(offered.as_deref())?;
            connection.authenticate(mechanism, user, password).await?;
        }
        Ok(connection)
    }

    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// One round-trip command: encode OP_MSG, read the reply, require
    /// `ok: 1`, map mongo error payloads onto the shared error type
    /// (code 18 = AuthenticationFailed -> `AuthFailed`).
    async fn command(&mut self, body: &Document) -> Result<Document, ConnectionError> {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        let frame = OpMsg::encode(request_id, body)?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|_| ConnectionError::NetworkFailure)?;
        let reply = OpMsg::read(&mut self.stream).await?;
        if reply.response_to != request_id {
            return Err(protocol(format!(
                "reply answers request {} while {} was in flight",
                reply.response_to, request_id
            )));
        }
        match ok_status(&reply.body) {
            Some(true) => Ok(reply.body),
            Some(false) => Err(command_error(&reply.body)),
            None => Err(protocol("reply lacks an 'ok' status field".to_owned())),
        }
    }

    /// SCRAM over `saslStart` / `saslContinue`. Mongo completes the
    /// client-final round in one extra `saslContinue`; the payload of
    /// its answer carries the server-final signature, verified locally
    /// against the RFC auth-message chain.
    async fn authenticate(
        &mut self,
        mechanism: Mechanism,
        user: &str,
        password: &str,
    ) -> Result<(), ConnectionError> {
        let mut scram = ScramClient::new(mechanism, user, password);
        let start = Document::from(vec![
            ("saslStart".to_owned(), Bson::Int32(1)),
            (
                "mechanism".to_owned(),
                Bson::String(mechanism.name().to_owned()),
            ),
            (
                "payload".to_owned(),
                Bson::Binary(scram.client_first().into_bytes()),
            ),
        ]);
        let reply = self.command(&start).await?;
        scram.server_first(&reply_payload(&reply)?)?;
        let conversation_id = int32_field(&reply, "conversationId");

        let final_payload = scram.client_final()?;
        let step = Document::from(vec![
            ("saslContinue".to_owned(), Bson::Int32(1)),
            ("conversationId".to_owned(), Bson::Int32(conversation_id)),
            (
                "payload".to_owned(),
                Bson::Binary(final_payload.into_bytes()),
            ),
        ]);
        let answer = self.command(&step).await?;
        let payload = reply_payload(&answer)?;
        let done = matches!(
            answer
                .iter()
                .find(|(key, _)| key == "done")
                .map(|(_, value)| value),
            Some(Bson::Boolean(true)) | Some(Bson::Int32(1)) | Some(Bson::Int64(1))
        );
        if !done {
            return Err(protocol(
                "server asked for unsupported extra SCRAM rounds".to_owned(),
            ));
        }
        scram.server_final(&payload)
    }

    /// One-shot `find`: `singleBatch` keeps the cursor closed so the
    /// reply is the whole answer; an open cursor id is a protocol error
    /// (batch resumption is the paging vertical).
    pub async fn find(&mut self, collection: &str) -> Result<Vec<Document>, ConnectionError> {
        let command = Document::from(vec![
            ("find".to_owned(), Bson::String(collection.to_owned())),
            ("filter".to_owned(), Bson::Document(Document::new())),
            ("singleBatch".to_owned(), Bson::Boolean(true)),
        ]);
        let reply = self.command(&command).await?;
        let Some((_, Bson::Document(cursor))) = reply.iter().find(|(key, _)| key == "cursor")
        else {
            return Err(protocol("find reply lacks a cursor document".to_owned()));
        };
        let cursor_id = cursor
            .iter()
            .find(|(key, _)| key == "id")
            .map(|(_, value)| value);
        let open_cursor = match cursor_id {
            Some(Bson::Int64(0)) | Some(Bson::Int32(0)) | Some(Bson::Double(0.0)) => None,
            Some(other) => Some(other.clone()),
            None => None,
        };
        if let Some(id) = open_cursor {
            return Err(protocol(format!(
                "find returned an open cursor ({id:?}): batch resumption is not supported yet"
            )));
        }
        let Some((_, Bson::Array(batch))) = cursor.iter().find(|(key, _)| key == "firstBatch")
        else {
            return Err(protocol("cursor lacks a firstBatch array".to_owned()));
        };
        batch
            .iter()
            .map(|document| match document {
                Bson::Document(document) => Ok(document.clone()),
                other => Err(protocol(format!(
                    "batch entry is not a document: {other:?}"
                ))),
            })
            .collect()
    }

    /// Keepalive command (`{ping: 1}`), the whole driver surface the
    /// connection lifecycle needs.
    pub async fn ping(&mut self) -> Result<(), ConnectionError> {
        let command = Document::from(vec![("ping".to_owned(), Bson::Int32(1))]);
        self.command(&command).await.map(|_| ())
    }

    /// Closes the TCP stream: drop-based; mongo has no close
    /// acknowledge like the postgres X message.
    pub async fn terminate(self) {}
}

fn offered_mechanisms(reply: &Document) -> Option<Vec<String>> {
    match reply.iter().find(|(key, _)| key == "saslSupportedMechs") {
        Some((_, Bson::Array(names))) => Some(
            names
                .iter()
                .filter_map(|name| match name {
                    Bson::String(text) => Some(text.clone()),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

fn reply_payload(reply: &Document) -> Result<Vec<u8>, ConnectionError> {
    match reply.iter().find(|(key, _)| key == "payload") {
        Some((_, Bson::Binary(bytes))) => Ok(bytes.clone()),
        Some((_, other)) => Err(protocol(format!("SCRAM payload is not binary: {other:?}"))),
        None => Err(protocol("SCRAM reply lacks a payload".to_owned())),
    }
}

fn ok_status(document: &Document) -> Option<bool> {
    let (_, status) = document.iter().find(|(key, _)| key == "ok")?;
    match status {
        Bson::Double(number) => Some(*number == 1.0),
        Bson::Int32(number) => Some(*number == 1),
        Bson::Int64(number) => Some(*number == 1),
        _ => None,
    }
}

fn command_error(document: &Document) -> ConnectionError {
    let code = match document
        .iter()
        .find(|(key, _)| key == "code")
        .map(|(_, v)| v)
    {
        Some(Bson::Int32(code)) => Some(*code),
        Some(Bson::Int64(code)) => Some(*code as i32),
        _ => None,
    };
    let message = match document.iter().find(|(key, _)| key == "errmsg") {
        Some((_, Bson::String(text))) => text.clone(),
        _ => "unknown".to_owned(),
    };
    if code == Some(18) {
        return ConnectionError::AuthFailed;
    }
    match code {
        Some(code) => ConnectionError::ExecutionFailed {
            sqlstate: None,
            message: format!("mongo command failed (code {code}): {message}"),
        },
        None => ConnectionError::ExecutionFailed {
            sqlstate: None,
            message: format!("mongo command failed: {message}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_parsing_covers_ok_shapes() {
        assert_eq!(ok_status(&status(1.0)), Some(true));
        assert_eq!(ok_status(&status(0.0)), Some(false));
        assert_eq!(
            ok_status(&Document::from(vec![("ok".to_owned(), Bson::Int32(1))])),
            Some(true)
        );
        assert_eq!(
            ok_status(&Document::from(vec![("ok".to_owned(), Bson::Int64(0))])),
            Some(false)
        );
        assert_eq!(
            ok_status(&Document::from(vec![("ok".to_owned(), Bson::Int32(5))])),
            Some(false)
        );
        assert_eq!(ok_status(&Document::new()), None);
    }

    fn status(ok: f64) -> Document {
        Document::from(vec![("ok".to_owned(), Bson::Double(ok))])
    }

    #[test]
    fn errors_map_code_18_to_auth_failed() {
        let error = command_error(&Document::from(vec![
            ("ok".to_owned(), Bson::Double(0.0)),
            ("code".to_owned(), Bson::Int32(18)),
            (
                "errmsg".to_owned(),
                Bson::String("Authentication failed.".to_owned()),
            ),
        ]));
        assert_eq!(error, ConnectionError::AuthFailed);

        let error = command_error(&Document::from(vec![
            ("ok".to_owned(), Bson::Double(0.0)),
            ("code".to_owned(), Bson::Int64(256)),
            ("errmsg".to_owned(), Bson::String("boom".to_owned())),
        ]));
        assert!(matches!(
            error,
            ConnectionError::ExecutionFailed { sqlstate: None, .. }
        ));
    }
}
