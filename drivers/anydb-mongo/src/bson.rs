//! BSON document parsing and typed mapping (DBeaver
//! `DocumentValueExtractor` analog): the typed foundation of the mongo
//! wire layer. BSON is self-delimiting (each document starts with its
//! own little-endian length), so parsing works on raw reply bytes with
//! no external dependency.
//!
//! Mapping contract (platform types only — see shared `TypedValue`):
//! - `double` -> `Float8`, `int32` -> `Int4`, `int64` -> `Int8`,
//!   `bool` -> `Boolean`, `string` -> `Text`, `binary` -> `Bytea` (raw
//!   bytes; the subtype is not preserved)
//! - embedded `document` / `array` -> `Text` with canonical mongo
//!   extended-JSON rendering (`{"$oid": ...}` / `{"$date": ...}`)
//! - `objectId` -> `Text` (24 lowercase hex chars)
//! - `utc datetime` -> `Text` (ISO-8601 UTC with milliseconds)
//! - `null` and a missing field -> no value (`None`)
//! - `timestamp` / `decimal128` -> `Bytea` (opaque raw bytes; text
//!   formats for them are out of scope)
//! - unsupported type bytes (regex, code, dbpointer, ...) are explicit
//!   `Protocol` errors, never silent degradation.

use anydb_shared::ConnectionError;
use anydb_shared::driver::statement::{TypedStatementResult, TypedValue};

/// BSON shape of a numeric literal: integers fit `Int32` when they can
/// (mongo shell convention), fall back to `Int64`; decimals and
/// exponents render as `Double`. Shared by the filter literal and the
/// insert document literal so both bind the same text to the same BSON
/// type; the CALLER owns any statement-context prefix in the message.
pub(crate) fn number_literal(raw: &str) -> Result<Bson, ConnectionError> {
    if let Ok(value) = raw.parse::<i32>() {
        return Ok(Bson::Int32(value));
    }
    if let Ok(value) = raw.parse::<i64>() {
        return Ok(Bson::Int64(value));
    }
    if !raw.contains(['.', 'e', 'E']) {
        return Err(ConnectionError::Protocol(format!(
            "integer literal '{raw}' does not fit i64"
        )));
    }
    raw.parse::<f64>()
        .map(Bson::Double)
        .map_err(|_| ConnectionError::Protocol(format!("invalid numeric literal '{raw}'")))
}

/// A parsed BSON value. Documents and arrays keep field order.
#[derive(Debug, Clone, PartialEq)]
pub enum Bson {
    Double(f64),
    String(String),
    Document(Document),
    Array(Vec<Bson>),
    Binary(Vec<u8>),
    ObjectId([u8; 12]),
    Boolean(bool),
    /// Milliseconds since the Unix epoch.
    DateTime(i64),
    /// Mongo oplog timestamp: seconds since the epoch plus a monotonic
    /// increment within that second.
    Timestamp {
        seconds: u32,
        increment: u32,
    },
    /// `decimal128` decoded to its decimal value object (IEEE 754-2008
    /// BID with the BSON byte layout).
    Decimal128(Decimal128),
    Null,
    Int32(i32),
    Int64(i64),
}

/// A decoded `decimal128` (dependency-free): sign, significand digits
/// and the unbiased exponent — exactly what the wire carries, in the
/// mongo canonical string shape (fixed notation when `-6 <= adjusted`,
/// scientific otherwise; `NaN` / `Infinity` for specials).
#[derive(Debug, Clone, PartialEq)]
pub struct Decimal128 {
    pub negative: bool,
    /// Significand digits without leading zeros (`"0"` for zero);
    /// significant trailing zeros are preserved (`"10"` renders `1.0`).
    pub digits: String,
    /// Unbiased exponent (biased field minus 6176).
    pub exponent: i32,
}

impl Decimal128 {
    /// Canonical mongo render (the `NumberDecimal(...)` payload), with
    /// the exact rules observed on a live mongod 7.0: exponent 0 renders
    /// the digits as-is, a positive exponent is always scientific
    /// (`1E+2`, `1.23E+5`), and a negative one is fixed while the
    /// adjusted exponent stays at or above `-6` (`0.00001`, `1.0`),
    /// scientific below it (`1E-7`). Zeros keep their scale (`0.0`).
    pub fn canonical(&self) -> String {
        if self.digits == "NaN" || self.digits == "Infinity" {
            let mut out = String::new();
            if self.negative {
                out.push('-');
            }
            out.push_str(&self.digits);
            return out;
        }
        let mut out = String::new();
        if self.negative {
            out.push('-');
        }
        let digits = &self.digits;
        let adjusted = self.exponent + digits.len() as i32 - 1;
        if self.exponent == 0 {
            out.push_str(digits);
        } else if self.exponent > 0 || adjusted < -6 {
            // Scientific: first digit, optional rest, signed adjusted
            // exponent.
            out.push_str(&digits[..1]);
            if digits.len() > 1 {
                out.push('.');
                out.push_str(&digits[1..]);
            }
            out.push('E');
            if adjusted >= 0 {
                out.push('+');
            }
            out.push_str(&adjusted.to_string());
        } else {
            // Fixed with the decimal point inside or before the digits.
            let point = digits.len() as i32 + self.exponent;
            if point <= 0 {
                out.push_str("0.");
                for _ in 0..(-point) {
                    out.push('0');
                }
                out.push_str(digits);
            } else {
                out.push_str(&digits[..point as usize]);
                out.push('.');
                out.push_str(&digits[point as usize..]);
            }
        }
        out
    }
}

/// Parses the canonical decimal text into a `Decimal128` (specials and
/// plain/scientific forms; the inverse of `Decimal128::canonical`).
pub fn parse_decimal128(text: &str) -> Result<Decimal128, ConnectionError> {
    let (negative, text) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    parse_positive(text, negative)
}

fn parse_positive(text: &str, negative: bool) -> Result<Decimal128, ConnectionError> {
    // NaN / Infinity first.
    if text == "NaN" || text == "Infinity" {
        return Ok(Decimal128 {
            negative,
            digits: text.to_owned(),
            exponent: 0,
        });
    }
    let invalid = || ConnectionError::Protocol(format!("invalid decimal128 literal '{text}'"));
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().map_err(|_| invalid())?),
        None => (text, 0),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (mantissa, ""),
    };
    if integer.is_empty() && fraction.is_empty() {
        return Err(invalid());
    }
    if !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let digits: String = integer.chars().chain(fraction.chars()).collect();
    // Trim leading zeros; a significand of only zeros is the zero value.
    let exponent = exponent - fraction.len() as i32;
    match digits.bytes().position(|byte| byte != b'0') {
        Some(position) => {
            let digits = &digits[position..];
            if digits.len() > 34 {
                return Err(protocol(format!(
                    "decimal128 significand '{}' exceeds 34 digits",
                    digits.len()
                )));
            }
            Ok(Decimal128 {
                negative,
                digits: digits.to_owned(),
                exponent,
            })
        }
        // Zero: one significant digit, sign and scale preserved
        // (`-0` and `0.0` render exactly as stored).
        None => Ok(Decimal128 {
            negative,
            digits: "0".to_owned(),
            exponent,
        }),
    }
}

/// The decimal128 exponent bias (`Emin = -6176`).
const DECIMAL128_BIAS: i32 = 6176;

/// Decodes the 16 wire bytes of a `decimal128`. Layout verified against
/// a live mongod 7.0 (byte order per the BSON decimal128 spec):
/// `b15` = sign bit 7 + biased exponent bits 13..7, `b14` bits 7..1 =
/// biased exponent bits 6..0 and bit 0 = coefficient bit 112, and
/// `b13..b0` = the remaining coefficient bits (little endian). Exponent
/// bias 6176; the coefficient is an integer of at most 34 decimal
/// digits. Top exponent bits mark the specials: biased field
/// `0x7C..` = NaN (payload ignored), `0x78..` = Infinity — the inverse
/// of the IEEE MSB-first bit numbering.
fn decimal128_decode(bytes: &[u8]) -> Result<Decimal128, ConnectionError> {
    let low = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
    let high = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
    let negative = (high >> 63) & 1 == 1;
    if (high >> 59) & 0x0F == 0x0F {
        let digits = if (high >> 58) & 1 == 1 {
            "NaN"
        } else {
            "Infinity"
        };
        return Ok(Decimal128 {
            negative,
            digits: digits.to_owned(),
            exponent: 0,
        });
    }

    let biased = (((high >> 56) & 0x7F) << 7) as i32 | ((high >> 49) & 0x7F) as i32;
    if biased > DECIMAL128_BIAS + 6111 {
        return Err(protocol(format!(
            "decimal128 exponent field out of range ({biased})"
        )));
    }
    let significand = (((high >> 48) & 1) as u128) << 112
        | (((high & 0xFFFF_FFFF_FFFF) as u128) << 64)
        | low as u128;
    let digits = significand.to_string();
    if digits.len() > 34 {
        return Err(protocol(format!(
            "decimal128 significand '{digits}' exceeds 34 digits"
        )));
    }
    Ok(Decimal128 {
        negative,
        digits,
        exponent: biased - DECIMAL128_BIAS,
    })
}

/// Encodes a `Decimal128` back to its 16 wire bytes (the round-trip
/// inverse of `decimal128_decode`).
fn decimal128_encode(value: &Decimal128) -> Result<[u8; 16], ConnectionError> {
    if value.digits == "NaN" {
        let high = 0x7C00_0000_0000_0000 | ((value.negative as u64) << 63);
        return Ok(le_bytes16(0, high));
    }
    if value.digits == "Infinity" {
        let high = 0x7800_0000_0000_0000 | ((value.negative as u64) << 63);
        return Ok(le_bytes16(0, high));
    }
    let significand = value
        .digits
        .parse::<u128>()
        .map_err(|_| protocol(format!("invalid decimal128 significand '{}'", value.digits)))?;
    if significand > 9_999_999_999_999_999_999_999_999_999_999_999u128 {
        return Err(protocol(format!(
            "decimal128 significand '{}' exceeds 34 digits",
            value.digits
        )));
    }
    let biased = value.exponent + DECIMAL128_BIAS;
    let biased = u32::try_from(biased)
        .ok()
        .filter(|biased| (0..=(DECIMAL128_BIAS + 6111) as u32).contains(biased))
        .ok_or_else(|| {
            protocol(format!(
                "decimal128 exponent {} out of range",
                value.exponent
            ))
        })?;
    // The significand spans high(49: bits 64..112) + low(64) bits; the
    // exponent field and the coefficient's top bit share the top word.
    let high = (((biased >> 7) as u64 & 0x7F) << 56)
        | (((biased & 0x7F) as u64) << 49)
        | (((significand >> 112) as u64 & 1) << 48)
        | ((significand >> 64) as u64 & 0xFFFF_FFFF_FFFF)
        | ((value.negative as u64) << 63);
    let low = significand as u64;
    Ok(le_bytes16(low, high))
}

fn le_bytes16(low: u64, high: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&low.to_le_bytes());
    bytes[8..16].copy_from_slice(&high.to_le_bytes());
    bytes
}

/// A parsed BSON document in field order.
pub type Document = Vec<(String, Bson)>;

fn protocol(message: String) -> ConnectionError {
    ConnectionError::Protocol(format!("malformed BSON: {message}"))
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ConnectionError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| protocol("truncated value".to_owned()))?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ConnectionError> {
        Ok(self.take(1)?[0])
    }

    fn i32_le(&mut self) -> Result<i32, ConnectionError> {
        let bytes = self.take(4)?;
        Ok(i32::from_le_bytes(bytes.try_into().expect("4 bytes")))
    }

    fn i64_le(&mut self) -> Result<i64, ConnectionError> {
        let bytes = self.take(8)?;
        Ok(i64::from_le_bytes(bytes.try_into().expect("8 bytes")))
    }

    fn f64_le(&mut self) -> Result<f64, ConnectionError> {
        let bytes = self.take(8)?;
        Ok(f64::from_le_bytes(bytes.try_into().expect("8 bytes")))
    }

    fn cstring(&mut self) -> Result<String, ConnectionError> {
        let start = self.position;
        let terminator = self.bytes[start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| start + offset);
        let Some(terminator) = terminator else {
            self.position = self.bytes.len();
            return Err(protocol("unterminated string".to_owned()));
        };
        let text = std::str::from_utf8(&self.bytes[start..terminator])
            .map_err(|_| protocol("invalid UTF-8 string".to_owned()))?;
        self.position = terminator + 1;
        Ok(text.to_owned())
    }

    fn value(&mut self, type_code: u8) -> Result<Bson, ConnectionError> {
        match type_code {
            0x01 => Ok(Bson::Double(self.f64_le()?)),
            0x02 => {
                let length = self.i32_le()?;
                let length = usize::try_from(length)
                    .map_err(|_| protocol("negative string length".to_owned()))?;
                if length == 0 {
                    return Err(protocol("empty string length".to_owned()));
                }
                let bytes = self.take(length - 1)?;
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| protocol("invalid UTF-8 string".to_owned()))?;
                match self.u8()? {
                    0 => (),
                    other => {
                        return Err(protocol(format!("string missing its NUL ({other:#06x})")));
                    }
                }
                Ok(Bson::String(text.to_owned()))
            }
            0x03 => Ok(Bson::Document(self.document_body()?)),
            0x04 => Ok(Bson::Array(
                self.document_body()?
                    .into_iter()
                    .map(|(_index_key, value)| value)
                    .collect(),
            )),
            0x05 => {
                let length = self.i32_le()?;
                let subtype = self.u8()?;
                let bytes = if subtype == 0x02 {
                    // Legacy subtype: an inner length prefix precedes the
                    // payload; its own length is authoritative there.
                    let inner = self.i32_le()?;
                    let inner = usize::try_from(inner)
                        .map_err(|_| protocol("negative legacy token length".to_owned()))?;
                    self.take(inner)?
                } else {
                    let length = usize::try_from(length)
                        .map_err(|_| protocol("negative binary length".to_owned()))?;
                    self.take(length)?
                };
                Ok(Bson::Binary(bytes.to_vec()))
            }
            0x07 => {
                let bytes = self.take(12)?;
                let mut object_id = [0u8; 12];
                object_id.copy_from_slice(bytes);
                Ok(Bson::ObjectId(object_id))
            }
            0x08 => match self.u8()? {
                0 => Ok(Bson::Boolean(false)),
                1 => Ok(Bson::Boolean(true)),
                other => Err(protocol(format!("invalid boolean byte {other}"))),
            },
            0x09 => Ok(Bson::DateTime(self.i64_le()?)),
            0x0A => Ok(Bson::Null),
            0x10 => Ok(Bson::Int32(self.i32_le()?)),
            0x11 => {
                // increment first, then the seconds since the epoch
                // (verified against a live mongod).
                let bytes = self.take(8)?;
                Ok(Bson::Timestamp {
                    seconds: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
                    increment: u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")),
                })
            }
            0x12 => Ok(Bson::Int64(self.i64_le()?)),
            0x13 => {
                let bytes = self.take(16)?;
                Ok(Bson::Decimal128(decimal128_decode(bytes)?))
            }
            other => Err(protocol(format!("unsupported type {other:#06x}"))),
        }
    }

    /// Reads one self-delimiting document (a nested value or the root):
    /// length, fields, terminator.
    fn document_body(&mut self) -> Result<Document, ConnectionError> {
        let body_start = self.position;
        let declared = self.i32_le()?;
        let declared = usize::try_from(declared)
            .ok()
            .filter(|declared| *declared >= 5)
            .ok_or_else(|| protocol("document too short".to_owned()))?;
        let end = body_start
            .checked_add(declared)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| protocol("document overruns its input".to_owned()))?;
        let mut document: Document = Vec::new();
        while self.position < end - 1 {
            let type_code = self.u8()?;
            let key = self.cstring()?;
            if self.position > end - 1 {
                return Err(protocol("field overruns its document".to_owned()));
            }
            let value = self.value(type_code)?;
            if self.position > end - 1 {
                return Err(protocol("value overruns its document".to_owned()));
            }
            document.push((key, value));
        }
        // Exactly one NUL terminator closes the document.
        self.take(1)?
            .first()
            .map(|byte| byte == &0)
            .filter(|terminated| *terminated)
            .ok_or_else(|| protocol("document missing its terminator".to_owned()))?;
        self.position = end;
        Ok(document)
    }
}

/// Parses one BSON document.
pub fn parse_document(input: &[u8]) -> Result<Document, ConnectionError> {
    let mut reader = Reader {
        bytes: input,
        position: 0,
    };
    reader.document_body()
}

/// Parses one BSON document, reporting the bytes it consumed (a
/// self-delimiting prefix of the input) — OP_MSG section walking needs
/// the exact boundary to prove nothing trails the section.
pub fn parse_document_len(input: &[u8]) -> Result<(Document, usize), ConnectionError> {
    let mut reader = Reader {
        bytes: input,
        position: 0,
    };
    let document = reader.document_body()?;
    Ok((document, reader.position))
}

/// Parses a stream of concatenated BSON documents (raw reply bodies).
pub fn parse_documents(input: &[u8]) -> Result<Vec<Document>, ConnectionError> {
    let mut reader = Reader {
        bytes: input,
        position: 0,
    };
    let mut documents = Vec::new();
    while reader.position < input.len() {
        documents.push(reader.document_body()?);
    }
    Ok(documents)
}

/// Platform-side typed value of one BSON value: `None` for `null`, so
/// the row slot stays empty.
pub fn typed_value(value: &Bson) -> Option<TypedValue> {
    match value {
        Bson::Double(number) => Some(TypedValue::Float8(*number)),
        Bson::String(text) => Some(TypedValue::Text(text.clone())),
        Bson::Document(_) | Bson::Array(_) => Some(TypedValue::Text(render(value))),
        Bson::Binary(bytes) => Some(TypedValue::Bytea(bytes.clone())),
        Bson::ObjectId(object_id) => Some(TypedValue::Text(object_id_hex(object_id))),
        Bson::Boolean(value) => Some(TypedValue::Boolean(*value)),
        Bson::DateTime(millis) => Some(TypedValue::Text(iso8601(*millis))),
        Bson::Timestamp { .. } => Some(TypedValue::Text(render(value))),
        Bson::Decimal128(value) => Some(TypedValue::BigDecimal(value.canonical())),
        Bson::Null => None,
        Bson::Int32(value) => Some(TypedValue::Int4(*value)),
        Bson::Int64(value) => Some(TypedValue::Int8(*value)),
    }
}

fn object_id_hex(bytes: &[u8; 12]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Maps one document to a row: columns follow field order, values are
/// aligned to them.
pub fn document_row(document: &Document) -> (Vec<String>, Vec<Option<TypedValue>>) {
    let columns = document
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    let values = document
        .iter()
        .map(|(_, value)| typed_value(value))
        .collect::<Vec<_>>();
    (columns, values)
}

/// Assembles a typed result from parsed documents: the columns are the
/// union of all fields in first-seen order, and each document becomes a
/// row aligned to the union (missing fields yield `None`).
pub fn documents_to_result(
    documents: &[Document],
    command_tag: Option<&str>,
    affected_rows: Option<i64>,
) -> TypedStatementResult {
    let mut columns: Vec<String> = Vec::new();
    for document in documents {
        for (key, _) in document {
            if !columns.iter().any(|column| column == key) {
                columns.push(key.clone());
            }
        }
    }
    let rows = documents
        .iter()
        .map(|document| {
            columns
                .iter()
                .map(|column| {
                    document
                        .iter()
                        .find(|(key, _)| key == column)
                        .and_then(|(_, value)| typed_value(value))
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    TypedStatementResult {
        columns,
        rows,
        command_tag: command_tag.map(|tag| tag.to_owned()),
        affected_rows,
    }
}

/// Canonical mongo extended-JSON rendering (embedded documents deliver
/// as `{"$oid": ...}` / `{"$date": ...}` wrappers, opaque bytes as the
/// `\x` hex convention).
fn render(value: &Bson) -> String {
    let mut out = String::new();
    render_into(value, &mut out);
    out
}

fn render_into(value: &Bson, out: &mut String) {
    match value {
        Bson::Double(number) => out.push_str(&TypedValue::Float8(*number).to_string()),
        Bson::String(text) => {
            out.push('"');
            escape_json(text, out);
            out.push('"');
        }
        Bson::Document(document) => {
            out.push('{');
            for (index, (key, nested)) in document.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push('"');
                escape_json(key, out);
                out.push_str("\": ");
                render_into(nested, out);
            }
            out.push('}');
        }
        Bson::Array(values) => {
            out.push('[');
            for (index, nested) in values.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                render_into(nested, out);
            }
            out.push(']');
        }
        Bson::Binary(bytes) => out.push_str(&TypedValue::Bytea(bytes.clone()).to_string()),
        Bson::ObjectId(object_id) => {
            out.push_str("{\"$oid\": \"");
            out.push_str(&object_id_hex(object_id));
            out.push_str("\"}");
        }
        Bson::Boolean(value) => out.push_str(if *value { "true" } else { "false" }),
        Bson::DateTime(millis) => {
            out.push_str("{\"$date\": \"");
            out.push_str(&iso8601(*millis));
            out.push_str("\"}");
        }
        Bson::Timestamp { seconds, increment } => {
            out.push_str("{\"$timestamp\": {\"t\": ");
            out.push_str(&seconds.to_string());
            out.push_str(", \"i\": ");
            out.push_str(&increment.to_string());
            out.push_str("}}");
        }
        Bson::Decimal128(value) => {
            out.push_str("{\"$numberDecimal\": \"");
            out.push_str(&value.canonical());
            out.push_str("\"}");
        }
        Bson::Null => out.push_str("null"),
        Bson::Int32(number) => out.push_str(&number.to_string()),
        Bson::Int64(number) => out.push_str(&number.to_string()),
    }
}

fn escape_json(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => out.push(other),
        }
    }
}

/// ISO-8601 UTC from milliseconds since the Unix epoch (no third-party
/// chrono: the proleptic Gregorian day conversion is
/// Howard Hinnant's `civil_from_days`).
fn iso8601(epoch_millis: i64) -> String {
    let seconds = epoch_millis.div_euclid(1000);
    let millis = epoch_millis.rem_euclid(1000) as u32;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = seconds_of_day % 3600 / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shift = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_shift + 2) / 5 + 1) as u32;
    let month = if month_shift < 10 {
        month_shift + 3
    } else {
        month_shift - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

// ---------- encoding (wire commands) ----------

/// Encodes one self-delimiting BSON document: little-endian length
/// prefix, fields, terminator. The inverse of `parse_document`, used to
/// build outgoing OP_MSG command bodies.
///
/// Key rules: keys must be non-empty and free of NUL bytes (a BSON body
/// is NUL-terminated per key). Opaque raw bytes (`timestamp` /
/// `decimal128`) encode as binary subtype 0x00 — opaque values never
/// leave as anything else on the wire surface this driver produces.
pub fn encode_document(document: &Document) -> Result<Vec<u8>, ConnectionError> {
    let mut fields = Vec::new();
    write_fields(document, &mut fields)?;
    let total = 4usize
        .checked_add(fields.len())
        .ok_or_else(|| protocol("document too large".to_owned()))?;
    i32::try_from(total).map_err(|_| protocol("document too large".to_owned()))?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as i32).to_le_bytes());
    out.extend_from_slice(&fields);
    Ok(out)
}

fn write_fields(document: &Document, out: &mut Vec<u8>) -> Result<(), ConnectionError> {
    for (key, value) in document {
        if key.is_empty() {
            return Err(protocol("empty field key".to_owned()));
        }
        if key.bytes().any(|byte| byte == 0) {
            return Err(protocol("field key contains a NUL byte".to_owned()));
        }
        let type_code = match value {
            Bson::Double(_) => 0x01,
            Bson::String(_) => 0x02,
            Bson::Document(_) => 0x03,
            Bson::Array(_) => 0x04,
            Bson::Binary(_) => 0x05,
            Bson::ObjectId(_) => 0x07,
            Bson::Boolean(_) => 0x08,
            Bson::DateTime(_) => 0x09,
            Bson::Null => 0x0A,
            Bson::Int32(_) => 0x10,
            Bson::Timestamp { .. } => 0x11,
            Bson::Int64(_) => 0x12,
            Bson::Decimal128(_) => 0x13,
        };
        out.push(type_code);
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        write_value(value, out)?;
    }
    out.push(0);
    Ok(())
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ConnectionError> {
    let length = i32::try_from(bytes.len()).map_err(|_| protocol("binary too large".to_owned()))?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_string(text: &str, out: &mut Vec<u8>) -> Result<(), ConnectionError> {
    let mut body = text.as_bytes().to_vec();
    body.push(0);
    write_bytes(out, &body)?;
    Ok(())
}

fn write_value(value: &Bson, out: &mut Vec<u8>) -> Result<(), ConnectionError> {
    match value {
        Bson::Double(number) => out.extend_from_slice(&number.to_le_bytes()),
        Bson::String(text) => write_string(text, out)?,
        Bson::Document(nested) => out.extend_from_slice(&encode_document(nested)?),
        Bson::Array(values) => {
            // BSON arrays are documents whose keys are the indexes.
            let indexed: Document = values
                .iter()
                .enumerate()
                .map(|(index, value)| (index.to_string(), value.clone()))
                .collect();
            out.extend_from_slice(&encode_document(&indexed)?);
        }
        Bson::Binary(bytes) => {
            let length =
                i32::try_from(bytes.len()).map_err(|_| protocol("binary too large".to_owned()))?;
            out.extend_from_slice(&length.to_le_bytes());
            out.push(0x00);
            out.extend_from_slice(bytes);
        }
        Bson::ObjectId(bytes) => out.extend_from_slice(bytes),
        Bson::Boolean(value) => out.push(u8::from(*value)),
        Bson::DateTime(millis) => out.extend_from_slice(&millis.to_le_bytes()),
        Bson::Timestamp { seconds, increment } => {
            // Wire order verified against a live mongod: increment
            // first, then the seconds.
            out.extend_from_slice(&increment.to_le_bytes());
            out.extend_from_slice(&seconds.to_le_bytes());
        }
        Bson::Decimal128(value) => {
            out.extend_from_slice(&decimal128_encode(value)?);
        }
        Bson::Null => {}
        Bson::Int32(number) => out.extend_from_slice(&number.to_le_bytes()),
        Bson::Int64(number) => out.extend_from_slice(&number.to_le_bytes()),
    }
    Ok(())
}

// ---------- test helpers (build raw BSON little-endian) ----------

#[cfg(test)]
fn test_field(type_code: u8, key: &str, mut value: Vec<u8>) -> Vec<u8> {
    let mut field = vec![type_code];
    field.extend_from_slice(key.as_bytes());
    field.push(0);
    field.append(&mut value);
    field
}

#[cfg(test)]
fn test_document(fields: Vec<Vec<u8>>) -> Vec<u8> {
    let mut body = fields;
    body.push(vec![0]);
    let mut bytes = ((4 + body.iter().map(Vec::len).sum::<usize>()) as i32)
        .to_le_bytes()
        .to_vec();
    for field in body {
        bytes.extend_from_slice(&field);
    }
    bytes
}

#[cfg(test)]
fn test_le32(value: i32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

#[cfg(test)]
fn test_le64(value: i64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

#[cfg(test)]
fn test_string_value(text: &str) -> Vec<u8> {
    let mut value = (text.len() as i32 + 1).to_le_bytes().to_vec();
    value.extend_from_slice(text.as_bytes());
    value.push(0);
    value
}

#[cfg(test)]
fn test_binary_value(subtype: u8, bytes: &[u8]) -> Vec<u8> {
    let mut value = (bytes.len() as i32).to_le_bytes().to_vec();
    value.push(subtype);
    value.extend_from_slice(bytes);
    value
}

#[cfg(test)]
fn test_double_value(value: f64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_common_scalar_set_into_platform_types() {
        let object_id_bytes = [
            0x10u8, 0x13, 0x16, 0x19, 0x1C, 0x1F, 0x22, 0x25, 0x28, 0x2B, 0x2E, 0x31,
        ];
        let input = test_document(vec![
            test_field(0x01, "ratio", test_double_value(3.5)),
            test_field(0x02, "name", test_string_value("hola")),
            test_field(0x08, "active", vec![1]),
            test_field(0x10, "count", test_le32(42)),
            test_field(0x12, "total", test_le64(9000)),
            test_field(0x0A, "missing", vec![]),
            test_field(0x09, "when", test_le64(1_735_689_600_000)),
            test_field(0x07, "id", object_id_bytes.to_vec()),
            test_field(0x05, "blob", test_binary_value(0, &[0xCA, 0xFE])),
        ]);
        let document = parse_document(&input).expect("parse");

        assert_eq!(document[0].0, "ratio");
        assert_eq!(document[0].1, Bson::Double(3.5));
        assert_eq!(
            typed_value(&Bson::String("hola".to_owned())),
            Some(TypedValue::Text("hola".to_owned()))
        );
        assert_eq!(
            typed_value(&Bson::Boolean(true)),
            Some(TypedValue::Boolean(true))
        );
        assert_eq!(typed_value(&Bson::Int32(42)), Some(TypedValue::Int4(42)));
        assert_eq!(
            typed_value(&Bson::Int64(9000)),
            Some(TypedValue::Int8(9000))
        );
        assert_eq!(typed_value(&Bson::Null), None);
        assert_eq!(
            typed_value(&Bson::DateTime(1_735_689_600_000)),
            Some(TypedValue::Text("2025-01-01T00:00:00.000Z".to_owned()))
        );
        assert_eq!(
            typed_value(&Bson::ObjectId(object_id_bytes)),
            Some(TypedValue::Text("101316191c1f2225282b2e31".to_owned()))
        );
        assert_eq!(
            typed_value(&Bson::Binary(vec![0xCA, 0xFE])),
            Some(TypedValue::Bytea(vec![0xCA, 0xFE]))
        );
    }

    #[test]
    fn maps_nan_doubles_without_partial_eq_traps() {
        let input = test_document(vec![test_field(0x01, "x", test_double_value(f64::NAN))]);
        let document = parse_document(&input).expect("parse");
        match typed_value(&document[0].1) {
            Some(TypedValue::Float8(value)) => assert!(value.is_nan()),
            other => panic!("expected NaN Float8, got {other:?}"),
        }
    }

    #[test]
    fn maps_embedded_documents_and_arrays_as_canonical_json() {
        let object_id_bytes = [
            0x10u8, 0x13, 0x16, 0x19, 0x1C, 0x1F, 0x22, 0x25, 0x28, 0x2B, 0x2E, 0x31,
        ];
        let inner = test_document(vec![
            test_field(0x10, "b", test_le32(1)),
            test_field(0x02, "c", test_string_value("x")),
            test_field(0x07, "id", object_id_bytes.to_vec()),
            test_field(0x09, "t", test_le64(0)),
        ]);
        let input = test_document(vec![test_field(0x03, "meta", inner)]);
        let document = parse_document(&input).expect("parse");
        // Embedded wrappers disambiguate nested object ids and datetimes.
        assert_eq!(
            typed_value(&document[0].1),
            Some(TypedValue::Text(
                concat!(
                    "{\"b\": 1, \"c\": \"x\", ",
                    "\"id\": {\"$oid\": \"101316191c1f2225282b2e31\"}, ",
                    "\"t\": {\"$date\": \"1970-01-01T00:00:00.000Z\"}}"
                )
                .to_owned()
            ))
        );
    }

    #[test]
    fn maps_arrays_and_extended_json_wrappers() {
        let object_id_bytes = [
            0x10u8, 0x13, 0x16, 0x19, 0x1C, 0x1F, 0x22, 0x25, 0x28, 0x2B, 0x2E, 0x31,
        ];
        let array = test_document(vec![
            test_field(0x10, "0", test_le32(1)),
            test_field(0x10, "1", test_le32(2)),
        ]);
        let input = test_document(vec![
            test_field(0x04, "items", array),
            test_field(0x07, "id", object_id_bytes.to_vec()),
            test_field(0x09, "when", test_le64(0)),
        ]);
        let document = parse_document(&input).expect("parse");
        assert_eq!(
            typed_value(&document[0].1),
            Some(TypedValue::Text("[1, 2]".to_owned()))
        );
        assert_eq!(
            typed_value(&document[1].1),
            Some(TypedValue::Text("101316191c1f2225282b2e31".to_owned())),
            "top-level objectId renders as plain hex"
        );
        assert_eq!(
            typed_value(&document[2].1),
            Some(TypedValue::Text("1970-01-01T00:00:00.000Z".to_owned())),
            "top-level utc datetime renders as plain ISO-8601"
        );
    }

    #[test]
    fn document_rows_follow_field_order() {
        let input = test_document(vec![
            test_field(0x02, "a", test_string_value("uno")),
            test_field(0x10, "b", test_le32(2)),
            test_field(0x0A, "c", vec![]),
        ]);
        let (columns, values) = document_row(&parse_document(&input).expect("parse"));
        assert_eq!(columns, vec!["a", "b", "c"]);
        assert_eq!(
            values,
            vec![
                Some(TypedValue::Text("uno".to_owned())),
                Some(TypedValue::Int4(2)),
                None,
            ]
        );
    }

    #[test]
    fn documents_result_unions_columns_first_seen() {
        let first = Document::from(vec![
            ("a".to_owned(), Bson::Int32(1)),
            ("b".to_owned(), Bson::Int32(2)),
        ]);
        let second = Document::from(vec![
            ("b".to_owned(), Bson::Int32(3)),
            ("c".to_owned(), Bson::Int64(4)),
        ]);
        let result = documents_to_result(&[first, second], Some("find 2"), Some(2));
        assert_eq!(result.columns, vec!["a", "b", "c"]);
        assert_eq!(
            result.rows,
            vec![
                vec![Some(TypedValue::Int4(1)), Some(TypedValue::Int4(2)), None,],
                vec![None, Some(TypedValue::Int4(3)), Some(TypedValue::Int8(4)),],
            ]
        );
        assert_eq!(result.command_tag.as_deref(), Some("find 2"));
        assert_eq!(result.affected_rows, Some(2));
    }

    #[test]
    fn parses_a_stream_of_concatenated_documents() {
        let one = test_document(vec![test_field(0x10, "x", test_le32(1))]);
        let two = test_document(vec![test_field(0x10, "x", test_le32(2))]);
        let mut stream = one;
        stream.extend_from_slice(&two);
        let documents = parse_documents(&stream).expect("parse stream");
        assert_eq!(documents.len(), 2);
        assert_eq!(documents[0][0].1, Bson::Int32(1));
        assert_eq!(documents[1][0].1, Bson::Int32(2));
    }

    #[test]
    fn error_paths_refuse_malformed_bson() {
        // Unsupported type byte (regex).
        let input = test_document(vec![test_field(0x0B, "r", vec![0x00, 0x00])]);
        assert!(matches!(
            parse_document(&input),
            Err(ConnectionError::Protocol(_))
        ));

        // Declared length overruns the input (truncated reply).
        let mut input = test_document(vec![test_field(0x10, "x", test_le32(1))]);
        input[0..4].copy_from_slice(&100i32.to_le_bytes());
        assert!(matches!(
            parse_document(&input),
            Err(ConnectionError::Protocol(message)) if message.contains("overruns")
        ));

        // Empty input.
        assert!(matches!(
            parse_document(&[]),
            Err(ConnectionError::Protocol(_))
        ));

        // Document too short (declared < 5).
        assert!(matches!(
            parse_document(&4i32.to_le_bytes()),
            Err(ConnectionError::Protocol(message)) if message.contains("too short")
        ));

        // Root without its terminator: length says one byte less than the
        // closing NUL requires.
        let mut short = test_document(vec![test_field(0x10, "x", test_le32(1))]);
        let declared = short.len() as i32 - 1;
        short[0..4].copy_from_slice(&declared.to_le_bytes());
        assert!(matches!(
            parse_document(&short),
            Err(ConnectionError::Protocol(_))
        ));

        // Invalid boolean byte.
        let input = test_document(vec![test_field(0x08, "b", vec![7])]);
        assert!(matches!(
            parse_document(&input),
            Err(ConnectionError::Protocol(message)) if message.contains("boolean")
        ));
    }

    #[test]
    fn datetime_converts_proleptic_gregorian_epochs() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_735_689_600_000), "2025-01-01T00:00:00.000Z");
        assert_eq!(
            iso8601(1_735_689_600_000 + 86_400_000 * 31),
            "2025-02-01T00:00:00.000Z"
        );
        // Before the epoch.
        assert_eq!(iso8601(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(iso8601(-86_400_000), "1969-12-31T00:00:00.000Z");
        // Leap-era edge: 2000-02-29 exists (951782400 s = 2000-02-29T00Z).
        assert_eq!(iso8601(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn encoding_round_trips_through_the_parser() {
        let document = Document::from(vec![
            ("d".to_owned(), Bson::Double(3.5)),
            ("s".to_owned(), Bson::String("hola".to_owned())),
            (
                "n".to_owned(),
                Bson::Document(Document::from(vec![("x".to_owned(), Bson::Int32(7))])),
            ),
            (
                "a".to_owned(),
                Bson::Array(vec![Bson::Int32(1), Bson::Int64(2)]),
            ),
            ("b".to_owned(), Bson::Binary(vec![0xCA, 0xFE])),
            (
                "o".to_owned(),
                Bson::ObjectId([1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            ),
            ("t".to_owned(), Bson::Boolean(true)),
            ("m".to_owned(), Bson::Int64(9000)),
            ("c".to_owned(), Bson::Int32(42)),
            ("z".to_owned(), Bson::Null),
            ("w".to_owned(), Bson::DateTime(1_735_689_600_000)),
        ]);
        let encoded = encode_document(&document).expect("encode");
        assert_eq!(parse_document(&encoded).expect("reparsed"), document);
        // The length prefix equals the encoded size exactly.
        let declared = i32::from_le_bytes(encoded[0..4].try_into().expect("4 bytes"));
        assert_eq!(declared as usize, encoded.len());
    }

    #[test]
    fn empty_and_nested_documents_encode_canonically() {
        let encoded = encode_document(&Document::new()).expect("encode");
        assert_eq!(encoded, vec![5, 0, 0, 0, 0]);
        let nested = Document::from(vec![("in".to_owned(), Bson::Document(Document::new()))]);
        let encoded = encode_document(&nested).expect("encode");
        assert_eq!(parse_document(&encoded).expect("reparsed"), nested);
    }

    #[test]
    fn encoding_refuses_invalid_and_oversized_keys() {
        assert!(matches!(
            encode_document(&Document::from(vec![("".to_owned(), Bson::Int32(1))])),
            Err(ConnectionError::Protocol(message)) if message.contains("empty")
        ));
        assert!(matches!(
            encode_document(&Document::from(vec![("a\0".to_owned(), Bson::Int32(1))])),
            Err(ConnectionError::Protocol(message)) if message.contains("NUL")
        ));
    }

    #[test]
    fn binary_values_lock_the_wire_layout() {
        let encoded = encode_document(&Document::from(vec![(
            "b".to_owned(),
            Bson::Binary(vec![0xCA, 0xFE]),
        )]))
        .expect("encode");
        assert_eq!(
            encoded,
            vec![15, 0, 0, 0, 0x05, b'b', 0, 2, 0, 0, 0, 0x00, 0xCA, 0xFE, 0],
            "BSON binary layout: [len LE][subtype][payload]"
        );
    }

    #[test]
    fn arrays_encode_as_index_key_documents() {
        let encoded = encode_document(&Document::from(vec![(
            "a".to_owned(),
            Bson::Array(vec![Bson::Int32(1), Bson::Int32(2)]),
        )]))
        .expect("encode");
        let document = parse_document(&encoded).expect("reparsed");
        match &document[0].1 {
            Bson::Array(values) => assert_eq!(values, &vec![Bson::Int32(1), Bson::Int32(2)]),
            other => panic!("expected array, got {other:?}"),
        }
    }

    /// Byte patterns captured from a live mongod 7.0 by inserting
    /// `NumberDecimal` literals through the shell and hex-dumping the
    /// find reply (examples/probe.rs); each entry is (wire bytes,
    /// expected canonical text).
    fn oracle_decimals() -> Vec<(Vec<u8>, &'static str)> {
        vec![
            (hex("01000000000000000000000000004030"), "1"),
            (hex("010000000000000000000000000040B0"), "-1"),
            (hex("40E20100000000000000000000003A30"), "123.456"),
            (hex("0F000000000000000000000000003E30"), "1.5"),
            (hex("01000000000000000000000000004430"), "1E+2"),
            (hex("010000000000000000000000000036B0"), "-0.00001"),
            (hex("01000000000000000000000000000831"), "1E+100"),
            (hex("00000000000000000000000000004030"), "0"),
            (hex("000000000000000000000000000040B0"), "-0"),
            (hex("00000000000000000000000000003E30"), "0.0"),
            (hex("00000000000000000000000000003EB0"), "-0.0"),
            (hex("CE040000000000000000000000004030"), "1230"),
            (hex("7B000000000000000000000000004630"), "1.23E+5"),
            (hex("05000000000000000000000000003E30"), "0.5"),
            (hex("0A000000000000000000000000003E30"), "1.0"),
            (hex("01000000000000000000000000003230"), "1E-7"),
            (hex("CE040000000000000000000000003E30"), "123.0"),
            (hex("00000000000000000000000000003630"), "0.00000"),
            (hex("0000000000000000000000000000007C"), "NaN"),
            (hex("00000000000000000000000000000078"), "Infinity"),
            (hex("000000000000000000000000000000F8"), "-Infinity"),
        ]
    }

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn decodes_decimal128_byte_patterns_captured_from_a_live_server() {
        for (bytes, expected) in oracle_decimals() {
            let input = test_document(vec![test_field(0x13, "x", bytes)]);
            let document = parse_document(&input).expect("parse");
            match &document[0].1 {
                Bson::Decimal128(value) => {
                    assert_eq!(value.canonical(), expected, "canonical mismatch");
                }
                other => panic!("expected Decimal128, got {other:?}"),
            }
        }
    }

    #[test]
    fn typed_surface_carries_decimals_and_timestamps() {
        let value = parse_decimal128("123.456").expect("parse");
        assert_eq!(
            typed_value(&Bson::Decimal128(value)),
            Some(TypedValue::BigDecimal("123.456".to_owned()))
        );
        assert_eq!(
            typed_value(&Bson::Timestamp {
                seconds: 1_735_689_600,
                increment: 5,
            }),
            Some(TypedValue::Text(
                "{\"$timestamp\": {\"t\": 1735689600, \"i\": 5}}".to_owned()
            ))
        );
    }

    #[test]
    fn timestamps_use_the_increment_first_wire_order() {
        // Timestamp(1735689600, 5) hex-dumped from a live mongod.
        let bytes = hex("0500000080857467");
        let input = test_document(vec![test_field(0x11, "ts", bytes.clone())]);
        let document = parse_document(&input).expect("parse");
        match &document[0].1 {
            Bson::Timestamp { seconds, increment } => {
                assert_eq!(*seconds, 1_735_689_600);
                assert_eq!(*increment, 5);
            }
            other => panic!("expected Timestamp, got {other:?}"),
        }
        let encoded = encode_document(&Document::from(vec![(
            "ts".to_owned(),
            Bson::Timestamp {
                seconds: 1_735_689_600,
                increment: 5,
            },
        )]))
        .expect("encode");
        assert_eq!(
            &encoded[8..16],
            &bytes[..],
            "wire order: increment, seconds"
        );
    }

    #[test]
    fn decimal128_round_trips_through_the_wire_bytes() {
        let values = [
            "1",
            "-1",
            "0",
            "-0",
            "0.0",
            "0.00000",
            "0E+5",
            "1E+2",
            "1.23E+5",
            "123.456",
            "1.5",
            "1E-7",
            "123.0",
            "1230",
            "1E+100",
            "1E-6176",
            "1E+6111",
            "9.9999E+6111",
            "9999999999999999999999999999999999",
            "1.234567890123456789012345678901234",
            "NaN",
            "Infinity",
            "-Infinity",
            "-NaN",
        ];
        for text in values {
            let value = parse_decimal128(text).expect("parse");
            let bytes = decimal128_encode(&value).expect("encode");
            let decoded = decimal128_decode(&bytes).expect("decode");
            assert_eq!(decoded, value, "round trip of {text}");
            assert_eq!(decoded.canonical(), value.canonical(), "render of {text}");
        }
    }

    #[test]
    fn decimal128_rejects_oversized_coefficients_and_exponents() {
        assert!(
            parse_decimal128("1.2345678901234567890123456789012345").is_err(),
            "35 digits"
        );
        assert!(
            decimal128_encode(&Decimal128 {
                negative: false,
                digits: "1".to_owned(),
                exponent: 6112,
            })
            .is_err(),
            "exponent above Emax"
        );
        // biased 14336 (> 12287): finite layout with an out-of-range
        // exponent field.
        let bytes = hex("00000000000000000000000000004070");
        let input = test_document(vec![test_field(0x13, "x", bytes)]);
        assert!(parse_document(&input).is_err(), "exponent field range");
    }

    #[test]
    fn decimal128_documents_round_trip_end_to_end() {
        let document = Document::from(vec![
            (
                "price".to_owned(),
                Bson::Decimal128(parse_decimal128("123.456").expect("parse")),
            ),
            (
                "ts".to_owned(),
                Bson::Timestamp {
                    seconds: 1_735_689_600,
                    increment: 5,
                },
            ),
        ]);
        let encoded = encode_document(&document).expect("encode");
        let reparsed = parse_document(&encoded).expect("reparsed");
        assert_eq!(reparsed, document);
        assert_eq!(
            render(&Bson::Decimal128(parse_decimal128("1.5").expect("parse"))),
            "{\"$numberDecimal\": \"1.5\"}"
        );
        assert_eq!(
            render(&Bson::Timestamp {
                seconds: 1_735_689_600,
                increment: 5,
            }),
            "{\"$timestamp\": {\"t\": 1735689600, \"i\": 5}}"
        );
    }
}
