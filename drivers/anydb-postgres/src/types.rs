//! Postgres type catalog (DBeaver `JDBCCatalog` / type-resolution analog):
//! maps well-known type OIDs to binary- and text-format decoders for the
//! shared `TypedValue` value object.
//!
//! Only the wire-safe built-ins are binary-decoded; unknown OIDs (numeric,
//! timestamps, composites, ...) stay in text format, which the caller
//! requests per column inside `Bind`.

use anydb_shared::ConnectionError;
use anydb_shared::driver::statement::TypedValue;

/// Well-known type OIDs (PostgreSQL `src/include/catalog/pg_type.dat`).
pub mod oid {
    pub const BOOL: i32 = 16;
    pub const BYTEA: i32 = 17;
    pub const NAME: i32 = 19;
    pub const INT2: i32 = 21;
    pub const INT4: i32 = 23;
    pub const INT8: i32 = 20;
    pub const TEXT: i32 = 25;
    pub const FLOAT4: i32 = 700;
    pub const FLOAT8: i32 = 701;
    pub const VARCHAR: i32 = 1043;
}

/// Whether the catalog can binary-decode `oid`: the caller requests format
/// 1 for that column and format 0 (text) otherwise.
pub fn binary_supported(oid: i32) -> bool {
    matches!(
        oid,
        oid::BOOL
            | oid::BYTEA
            | oid::NAME
            | oid::INT2
            | oid::INT4
            | oid::INT8
            | oid::TEXT
            | oid::FLOAT4
            | oid::FLOAT8
            | oid::VARCHAR
    )
}

/// Decodes one binary-format value. `Ok(None)` means the OID is outside the
/// catalog (the caller should not have requested binary for it); a garbage
/// payload for a supported OID is a protocol error.
pub fn binary_decode(oid: i32, bytes: &[u8]) -> Result<Option<TypedValue>, ConnectionError> {
    let truncated = |expected: &str| {
        Err(ConnectionError::Protocol(format!(
            "truncated binary {expected} value"
        )))
    };
    match oid {
        oid::BOOL => match bytes {
            [0] => Ok(Some(TypedValue::Boolean(false))),
            [1] => Ok(Some(TypedValue::Boolean(true))),
            _ => truncated("bool"),
        },
        oid::INT2 => match bytes.try_into() {
            Ok(raw) => Ok(Some(TypedValue::Int2(i16::from_be_bytes(raw)))),
            _ => truncated("int2"),
        },
        oid::INT4 => match bytes.try_into() {
            Ok(raw) => Ok(Some(TypedValue::Int4(i32::from_be_bytes(raw)))),
            _ => truncated("int4"),
        },
        oid::INT8 => match bytes.try_into() {
            Ok(raw) => Ok(Some(TypedValue::Int8(i64::from_be_bytes(raw)))),
            _ => truncated("int8"),
        },
        oid::FLOAT4 => match bytes.try_into() {
            Ok(raw) => Ok(Some(TypedValue::Float4(f32::from_be_bytes(raw)))),
            _ => truncated("float4"),
        },
        oid::FLOAT8 => match bytes.try_into() {
            Ok(raw) => Ok(Some(TypedValue::Float8(f64::from_be_bytes(raw)))),
            _ => truncated("float8"),
        },
        // Raw value bytes; the framing already stripped the i32 length.
        oid::BYTEA => Ok(Some(TypedValue::Bytea(bytes.to_vec()))),
        // Raw UTF-8 text payload.
        oid::TEXT | oid::VARCHAR => match std::str::from_utf8(bytes) {
            Ok(value) => Ok(Some(TypedValue::Text(value.to_owned()))),
            _ => truncated("text"),
        },
        // Fixed-size NUL-padded name buffer (64 bytes today).
        oid::NAME => {
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            Ok(Some(TypedValue::Text(
                String::from_utf8_lossy(&bytes[..end]).into_owned(),
            )))
        }
        _ => Ok(None),
    }
}

/// Decodes one text-format value. Unknown OIDs degrade to raw text (the
/// server prints everything as readable text), so the catalog never blocks
/// a query; malformed cataloged values are protocol errors.
pub fn text_decode(oid: i32, bytes: &[u8]) -> Result<TypedValue, ConnectionError> {
    let value = String::from_utf8_lossy(bytes);
    let malformed = |kind: &str| ConnectionError::Protocol(format!("malformed text {kind} value"));
    match oid {
        oid::BOOL => match value.as_ref() {
            "t" | "true" => Ok(TypedValue::Boolean(true)),
            "f" | "false" => Ok(TypedValue::Boolean(false)),
            _ => Err(malformed("bool")),
        },
        oid::INT2 => value
            .parse::<i16>()
            .map(TypedValue::Int2)
            .map_err(|_| malformed("int2")),
        oid::INT4 => value
            .parse::<i32>()
            .map(TypedValue::Int4)
            .map_err(|_| malformed("int4")),
        oid::INT8 => value
            .parse::<i64>()
            .map(TypedValue::Int8)
            .map_err(|_| malformed("int8")),
        oid::FLOAT4 => value
            .parse::<f32>()
            .map(TypedValue::Float4)
            .map_err(|_| malformed("float4")),
        oid::FLOAT8 => value
            .parse::<f64>()
            .map(TypedValue::Float8)
            .map_err(|_| malformed("float8")),
        oid::BYTEA => decode_bytea_text(&value),
        oid::NAME => Ok(TypedValue::Text(value.into_owned())),
        oid::TEXT | oid::VARCHAR => Ok(TypedValue::Text(value.into_owned())),
        _ => Ok(TypedValue::Text(value.into_owned())),
    }
}

/// Postgres prints bytea as `\x` plus lowercase hex.
fn decode_bytea_text(value: &str) -> Result<TypedValue, ConnectionError> {
    let Some(hex) = value.strip_prefix("\\x") else {
        return Err(ConnectionError::Protocol(
            "malformed text bytea value (missing \\x prefix)".to_owned(),
        ));
    };
    if hex.len() % 2 != 0 {
        return Err(ConnectionError::Protocol(
            "malformed text bytea value (odd hex length)".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in 0..hex.len() / 2 {
        match u8::from_str_radix(&hex[pair * 2..pair * 2 + 2], 16) {
            Ok(byte) => bytes.push(byte),
            _ => {
                return Err(ConnectionError::Protocol(
                    "malformed hex in text bytea".to_owned(),
                ));
            }
        }
    }
    Ok(TypedValue::Bytea(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(oid: i32, bytes: &[u8]) -> TypedValue {
        binary_decode(oid, bytes)
            .expect("cataloged oid")
            .expect("decodes")
    }

    #[test]
    fn binary_catalog_round_trips_exact_widths() {
        assert_eq!(decode(16, &[1]), TypedValue::Boolean(true));
        assert_eq!(decode(21, &42i16.to_be_bytes()), TypedValue::Int2(42));
        assert_eq!(decode(23, &7i32.to_be_bytes()), TypedValue::Int4(7));
        assert_eq!(
            decode(20, &(i64::MIN).to_be_bytes()),
            TypedValue::Int8(i64::MIN)
        );
        assert_eq!(decode(700, &1.5f32.to_be_bytes()), TypedValue::Float4(1.5));
        assert_eq!(decode(701, &2.5f64.to_be_bytes()), TypedValue::Float8(2.5));
        assert_eq!(decode(25, b"hola"), TypedValue::Text("hola".into()));
        assert_eq!(decode(1043, b"v"), TypedValue::Text("v".into()));
        assert_eq!(decode(17, &[0xFF, 0x00]), TypedValue::Bytea(vec![255, 0]));
    }

    #[test]
    fn binary_trims_padded_name_and_rejects_unknown_oids() {
        let mut raw = [0u8; 64];
        raw[..5].copy_from_slice(b"users");
        assert_eq!(decode(19, &raw), TypedValue::Text("users".into()));

        assert_eq!(binary_decode(1700, b"1.23"), Ok(None));
        assert!(binary_supported(20));
        assert!(!binary_supported(1700));
    }

    #[test]
    fn binary_malformed_payloads_are_protocol_errors() {
        assert!(binary_decode(16, &[7]).is_err());
        assert!(binary_decode(20, b"long").is_err());
        assert!(binary_decode(25, &[0xFF, 0xFE]).is_err());
    }

    #[test]
    fn text_catalog_parses_canonical_output() {
        assert_eq!(text_decode(16, b"t"), Ok(TypedValue::Boolean(true)));
        assert_eq!(text_decode(16, b"false"), Ok(TypedValue::Boolean(false)));
        assert_eq!(text_decode(20, b"42"), Ok(TypedValue::Int8(42)));
        assert_eq!(text_decode(701, b"2.5"), Ok(TypedValue::Float8(2.5)));
        let non_finite = text_decode(701, b"NaN").expect("NaN decodes");
        assert!(matches!(non_finite, TypedValue::Float8(value) if value.is_nan()));
        assert_eq!(
            text_decode(700, b"Infinity"),
            Ok(TypedValue::Float4(f32::INFINITY))
        );
        assert_eq!(
            text_decode(1700, b"1.23"),
            Ok(TypedValue::Text("1.23".into()))
        );
        assert!(text_decode(20, b"nan").is_err());
    }

    #[test]
    fn text_bytea_hex_decodes_and_detects_malformed() {
        assert_eq!(
            text_decode(17, b"\\x4869"),
            Ok(TypedValue::Bytea(b"Hi".to_vec()))
        );
        assert_eq!(text_decode(17, b"\\x"), Ok(TypedValue::Bytea(vec![])));
        assert!(text_decode(17, b"Hi").is_err());
        assert!(text_decode(17, b"\\x48g").is_err());
    }

    #[test]
    fn display_is_platform_friendly() {
        assert_eq!(TypedValue::Boolean(false).to_string(), "false");
        assert_eq!(TypedValue::Int8(3).to_string(), "3");
        assert_eq!(TypedValue::Float8(4.0).to_string(), "4");
        assert_eq!(TypedValue::Float8(f64::NAN).to_string(), "NaN");
        assert_eq!(TypedValue::Bytea(b"Hi".to_vec()).to_string(), "\\x4869");
        assert_eq!(TypedValue::Text("a".into()).to_string(), "a");
    }
}
