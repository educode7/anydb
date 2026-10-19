//! OP_MSG framing (server protocol since 3.6): one 16-byte header with
//! the four little-endian `i32` fields, a flags word and the message
//! body as exactly one BSON document. Outgoing bodies are always a
//! single type-0 section; incoming bodies are restricted the same way
//! (extra sections, checksummed or `moreToCome` messages are explicit
//! `Protocol` errors instead of silent skips).

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::bson::{self, Document};
use anydb_shared::ConnectionError;

pub const OP_MSG_OPCODE: i32 = 2013;

const HEADER_SIZE: usize = 16;
/// The server spec's 48 MiB message cap; replies over it are protocol
/// violations we refuse to buffer.
const MAX_MESSAGE_SIZE: usize = 48 * 1024 * 1024;

fn protocol(message: String) -> ConnectionError {
    ConnectionError::Protocol(format!("OP_MSG: {message}"))
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpMsg {
    pub request_id: i32,
    pub response_to: i32,
    pub flags: i32,
    pub body: Document,
}

impl OpMsg {
    /// One reply frame over any byte source (TCP or TLS). Rejects flags
    /// the driver does not support and trailing bytes after the single
    /// body document.
    pub async fn read(stream: &mut (impl AsyncRead + Unpin)) -> Result<Self, ConnectionError> {
        let mut header = [0u8; HEADER_SIZE];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| ConnectionError::NetworkFailure)?;
        let length = i32::from_le_bytes(header[0..4].try_into().expect("4 bytes"));
        let request_id = i32::from_le_bytes(header[4..8].try_into().expect("4 bytes"));
        let response_to = i32::from_le_bytes(header[8..12].try_into().expect("4 bytes"));
        let opcode = i32::from_le_bytes(header[12..16].try_into().expect("4 bytes"));
        let length =
            usize::try_from(length).map_err(|_| protocol("negative message length".to_owned()))?;
        if length < HEADER_SIZE {
            return Err(protocol("message shorter than its header".to_owned()));
        }
        if length > MAX_MESSAGE_SIZE {
            return Err(protocol(format!(
                "message of {length} bytes exceeds the {MAX_MESSAGE_SIZE}-byte cap"
            )));
        }
        if opcode != OP_MSG_OPCODE {
            return Err(protocol(format!(
                "unexpected opcode {opcode} (expected OP_MSG)"
            )));
        }
        let mut body = vec![0u8; length - HEADER_SIZE];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|_| ConnectionError::NetworkFailure)?;
        if body.len() < 8 {
            return Err(protocol(
                "body too small to carry flags + a document".to_owned(),
            ));
        }
        let flags = i32::from_le_bytes(body[0..4].try_into().expect("4 bytes"));
        if flags != 0 {
            return Err(protocol(format!(
                "flags {flags:#010x} are not supported (checksums/moreToCome rejected)"
            )));
        }
        let document = bson::parse_document(&body[4..])?;
        Ok(Self {
            request_id,
            response_to,
            flags,
            body: document,
        })
    }

    /// One command frame with a fresh request id; the reply matcher on
    /// the connection uses `response_to` ordering.
    pub fn encode(request_id: i32, body: &Document) -> Result<Vec<u8>, ConnectionError> {
        let document = bson::encode_document(body)?;
        let length = (HEADER_SIZE + 4)
            .checked_add(document.len())
            .ok_or_else(|| protocol("message too large".to_owned()))?;
        if length > MAX_MESSAGE_SIZE {
            return Err(protocol("message too large".to_owned()));
        }
        let length_i32 =
            i32::try_from(length).map_err(|_| protocol("message too large".to_owned()))?;
        let mut out = Vec::with_capacity(length);
        out.extend_from_slice(&length_i32.to_le_bytes());
        out.extend_from_slice(&request_id.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&OP_MSG_OPCODE.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&document);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(value: i32) -> Document {
        Document::from(vec![("x".to_owned(), crate::bson::Bson::Int32(value))])
    }

    #[test]
    fn frames_carry_the_header_and_single_section() {
        let frame = OpMsg::encode(7, &document(1)).expect("encode");
        assert_eq!(
            &frame[0..4],
            &(frame.len() as i32).to_le_bytes(),
            "declared length matches the frame size"
        );
        assert_eq!(&frame[4..8], &7i32.to_le_bytes());
        assert_eq!(&frame[8..12], &0i32.to_le_bytes());
        assert_eq!(&frame[12..16], &OP_MSG_OPCODE.to_le_bytes());
        assert_eq!(&frame[16..20], &0i32.to_le_bytes(), "flags word is zero");
        let parsed = bson::parse_document(&frame[20..]).expect("body parses");
        assert_eq!(parsed, document(1));
    }

    #[test]
    fn oversized_bodies_are_rejected() {
        let huge = vec![
            (
                "blob".to_owned(),
                crate::bson::Bson::Binary(vec![0u8; 50 * 1024 * 1024]),
            ),
            ("ok".to_owned(), crate::bson::Bson::Int32(1)),
        ];
        assert!(OpMsg::encode(1, &huge).is_err());
    }
}
