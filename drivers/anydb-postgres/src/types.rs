//! Postgres type catalog (DBeaver `JDBCCatalog` / type-resolution analog):
//! maps well-known type OIDs to binary- and text-format decoders for the
//! shared `TypedValue` value object.
//!
//! Only the wire-safe built-ins are binary-decoded; unknown OIDs (timestamps,
//! composites, ...) stay in text format, which the caller requests per
//! column inside `Bind`.

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
    pub const NUMERIC: i32 = 1700;
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
            | oid::NUMERIC
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
        oid::NUMERIC => numeric_decode(bytes).map(Some),
        _ => Ok(None),
    }
}

// ---------- numeric (OID 1700) ----------

/// Sign markers of the numeric binary format (`numeric.c`; the external
/// format NEVER uses the internal short header — `numeric_recv` demands
/// one of these five values exactly).
const NUMERIC_POS: u16 = 0x0000;
const NUMERIC_NEG: u16 = 0x4000;
const NUMERIC_NAN: u16 = 0xC000;
const NUMERIC_PINF: u16 = 0xD000;
const NUMERIC_NINF: u16 = 0xF000;
/// Display-scale field is 14 bits (`NUMERIC_DSCALE_MASK`).
const NUMERIC_DSCALE_MASK: u16 = 0x3FFF;
/// Base-10000 digit groups (`NBASE`).
const NUMERIC_BASE: u16 = 10000;

/// Decodes the `numeric` binary format (`numeric_recv`): ndigits, weight,
/// sign, dscale as int16's, then `ndigits` base-10000 digit groups. The
/// value is `Σ d_i·10000^(weight - i)`; specials (NaN, ±Infinity) carry
/// no digits and render as text like postgres `numeric_out`.
fn numeric_decode(bytes: &[u8]) -> Result<TypedValue, ConnectionError> {
    let truncated = || {
        Err(ConnectionError::Protocol(
            "truncated binary numeric value".to_owned(),
        ))
    };
    let [b0, b1, b2, b3, b4, b5, b6, b7, rest @ ..] = bytes else {
        return truncated();
    };
    let ndigits = u16::from_be_bytes([*b0, *b1]);
    let weight = i16::from_be_bytes([*b2, *b3]);
    let sign = u16::from_be_bytes([*b4, *b5]);
    let dscale = u16::from_be_bytes([*b6, *b7]);

    match sign {
        NUMERIC_POS | NUMERIC_NEG => {}
        NUMERIC_NAN => return Ok(TypedValue::BigDecimal("NaN".to_owned())),
        NUMERIC_PINF => return Ok(TypedValue::BigDecimal("Infinity".to_owned())),
        NUMERIC_NINF => return Ok(TypedValue::BigDecimal("-Infinity".to_owned())),
        _ => {
            return Err(ConnectionError::Protocol(
                "invalid sign in external \"numeric\" value".to_owned(),
            ));
        }
    }
    if dscale & NUMERIC_DSCALE_MASK != dscale {
        return Err(ConnectionError::Protocol(
            "invalid scale in external \"numeric\" value".to_owned(),
        ));
    }
    if rest.len() != ndigits as usize * 2 {
        return truncated();
    }
    let mut groups = Vec::with_capacity(ndigits as usize);
    for index in (0..rest.len()).step_by(2) {
        let digit = u16::from_be_bytes([rest[index], rest[index + 1]]);
        if digit >= NUMERIC_BASE {
            return Err(ConnectionError::Protocol(
                "invalid digit in external \"numeric\" value".to_owned(),
            ));
        }
        groups.push(digit);
    }
    Ok(render_numeric(sign == NUMERIC_NEG, weight, dscale, &groups))
}

/// Renders the digit groups as exact decimal text in postgres
/// `numeric_out` shape: plain notation with exactly `dscale` decimals
/// when `dscale > 0` (the wire stores the display scale, so `1.5`
/// within `numeric(10,3)` renders `1.500`, never `1.5`).
///
/// Derivation (pure string math, no bignum arithmetic): with all groups
/// zero-padded to 4 digits the concatenated string is `D`, and the
/// value is `D · 10^E` with `E = 4·(weight - ndigits + 1)`. Verified
/// against live server payloads (see the numeric smoke example).
fn render_numeric(negative: bool, weight: i16, dscale: u16, groups: &[u16]) -> TypedValue {
    let padded: String = groups.iter().map(|digit| format!("{digit:04}")).collect();
    let ndigits = groups.len() as i64;
    let exponent = 4 * (weight as i64 - ndigits + 1);

    // Split the digit string at the decimal point. `exponent > 0` only
    // arises for zero values with no digits (ndigits == 0).
    let (int_raw, frac_full) = if exponent >= 0 {
        (
            format!("{padded}{}", "0".repeat(exponent as usize)),
            String::new(),
        )
    } else {
        let fraction = (-exponent) as usize;
        if padded.len() >= fraction {
            (
                padded[..padded.len() - fraction].to_owned(),
                padded[padded.len() - fraction..].to_owned(),
            )
        } else {
            (
                String::new(),
                format!("{}{padded}", "0".repeat(fraction - padded.len())),
            )
        }
    };

    let mut int = int_raw.trim_start_matches('0').to_owned();
    if int.is_empty() {
        int.push('0');
    }
    let mut text = String::with_capacity(int.len() + dscale as usize + 2);
    if negative {
        text.push('-');
    }
    text.push_str(&int);
    if dscale > 0 {
        text.push('.');
        let mut fraction = frac_full;
        while fraction.len() < dscale as usize {
            fraction.push('0');
        }
        fraction.truncate(dscale as usize);
        text.push_str(&fraction);
    }
    TypedValue::BigDecimal(text)
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
        // numeric_out prints plain notation (never scientific) plus the
        // three special spellings; validate that shape into BigDecimal.
        oid::NUMERIC => decode_numeric_text(&value),
        _ => Ok(TypedValue::Text(value.into_owned())),
    }
}

/// Validates the `numeric_out` text shape into `BigDecimal`.
fn decode_numeric_text(value: &str) -> Result<TypedValue, ConnectionError> {
    let malformed = ConnectionError::Protocol("malformed text numeric value".to_owned());
    match value {
        "NaN" => return Ok(TypedValue::BigDecimal("NaN".to_owned())),
        "Infinity" => return Ok(TypedValue::BigDecimal("Infinity".to_owned())),
        "-Infinity" => return Ok(TypedValue::BigDecimal("-Infinity".to_owned())),
        _ => {}
    }
    let body = value.strip_prefix(['-', '+']).unwrap_or(value);
    let negative = value.starts_with('-');
    let (whole, fraction) = match body.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty() || fraction.contains('.') {
                return Err(malformed);
            }
            (whole, fraction)
        }
        None => (body, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return Err(malformed);
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !fraction.chars().all(|c| c.is_ascii_digit()) {
        return Err(malformed);
    }
    // Pass through byte-for-byte (the wire carries the display scale
    // and this path exists only when binary was not requested).
    let text = if negative {
        format!("-{body}")
    } else {
        body.to_owned()
    };
    Ok(TypedValue::BigDecimal(text))
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

        assert_eq!(binary_decode(345, b"1.23"), Ok(None));
        assert!(binary_supported(20));
        assert!(binary_supported(1700));
    }

    /// Builds a numeric binary payload: ndigits, weight, sign, dscale,
    /// then each base-10000 digit group as int16.
    fn numeric_payload(weight: i16, sign: u16, dscale: u16, groups: &[u16]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(groups.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&weight.to_be_bytes());
        bytes.extend_from_slice(&sign.to_be_bytes());
        bytes.extend_from_slice(&dscale.to_be_bytes());
        for group in groups {
            bytes.extend_from_slice(&group.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn numeric_binary_renders_the_live_server_layout() {
        use oid::NUMERIC as N;
        // `150` — one group, weight 0, no display scale.
        assert_eq!(
            decode(N, &numeric_payload(0, 0x0000, 0, &[150])),
            TypedValue::BigDecimal("150".into())
        );
        // `15000` — the integer part spills into a second group (weight 1).
        assert_eq!(
            decode(N, &numeric_payload(1, 0x0000, 0, &[1, 5000])),
            TypedValue::BigDecimal("15000".into())
        );
        // `150.5` — fractional group padded to four digits.
        assert_eq!(
            decode(N, &numeric_payload(0, 0x0000, 1, &[150, 5000])),
            TypedValue::BigDecimal("150.5".into())
        );
        // `0.005` — negative weight, the leading zeros are implied.
        assert_eq!(
            decode(N, &numeric_payload(-1, 0x0000, 3, &[50])),
            TypedValue::BigDecimal("0.005".into())
        );
        // `1.50003` — fractional group split across positions.
        assert_eq!(
            decode(N, &numeric_payload(0, 0x0000, 5, &[1, 5000, 3000])),
            TypedValue::BigDecimal("1.50003".into())
        );
        // `0.0000001` — small exponents keep every zero.
        assert_eq!(
            decode(N, &numeric_payload(-1, 0x0000, 7, &[0, 10])),
            TypedValue::BigDecimal("0.0000001".into())
        );
        // `-150.5` — sign bit only, digits stay unsigned.
        assert_eq!(
            decode(N, &numeric_payload(0, 0x4000, 1, &[150, 5000])),
            TypedValue::BigDecimal("-150.5".into())
        );
        // `1.500` — the display scale is wire data: `numeric(10,3)` keeps
        // trailing zeros in the rendered text.
        assert_eq!(
            decode(N, &numeric_payload(0, 0x0000, 3, &[1, 5000])),
            TypedValue::BigDecimal("1.500".into())
        );
        // Zero value: no digit groups at all, scale-only rendering.
        assert_eq!(
            decode(N, &numeric_payload(0, 0x0000, 2, &[])),
            TypedValue::BigDecimal("0.00".into())
        );
        // Specials carry no digits and render like numeric_out.
        assert_eq!(
            decode(N, &numeric_payload(0, 0xC000, 0, &[])),
            TypedValue::BigDecimal("NaN".into())
        );
        assert_eq!(
            decode(N, &numeric_payload(0, 0xD000, 0, &[])),
            TypedValue::BigDecimal("Infinity".into())
        );
        assert_eq!(
            decode(N, &numeric_payload(0, 0xF000, 0, &[])),
            TypedValue::BigDecimal("-Infinity".into())
        );
    }

    #[test]
    fn numeric_binary_rejects_what_numeric_recv_rejects() {
        use oid::NUMERIC as N;
        // Sign must be one of the five markers exactly.
        assert!(binary_decode(N, &numeric_payload(0, 0x2000, 0, &[])).is_err());
        assert!(binary_decode(N, &numeric_payload(0, 0x8000, 0, &[])).is_err());
        // dscale overflows the 14-bit mask.
        assert!(binary_decode(N, &numeric_payload(0, 0x0000, 0x4000, &[])).is_err());
        // Digit groups are 0..9999.
        assert!(binary_decode(N, &numeric_payload(0, 0x0000, 0, &[10000])).is_err());
        // Truncated header and digit-count mismatch are protocol errors.
        assert!(binary_decode(N, &[0, 1, 0, 0, 0, 0, 0, 0]).is_err());
        // Two declared digits but only one group present.
        let mut short = numeric_payload(0, 0x0000, 0, &[1]);
        short[0] = 0;
        short[1] = 2;
        assert!(binary_decode(N, &short).is_err());
        assert_eq!(
            binary_decode(N, &numeric_payload(0, 0x0000, 0, &[1, 2])[..7]),
            Err(ConnectionError::Protocol(
                "truncated binary numeric value".into()
            ))
        );
    }

    #[test]
    fn numeric_text_validates_the_output_shape() {
        use oid::NUMERIC as N;
        assert_eq!(
            text_decode(N, b"123.456"),
            Ok(TypedValue::BigDecimal("123.456".into()))
        );
        assert_eq!(
            text_decode(N, b"-150"),
            Ok(TypedValue::BigDecimal("-150".into()))
        );
        assert_eq!(
            text_decode(N, b"NaN"),
            Ok(TypedValue::BigDecimal("NaN".into()))
        );
        assert_eq!(
            text_decode(N, b"-Infinity"),
            Ok(TypedValue::BigDecimal("-Infinity".into()))
        );
        // The text path never receives scientific notation (numeric_out
        // prints plain); garbage shapes are protocol errors.
        assert!(text_decode(N, b"1e5").is_err());
        assert!(text_decode(N, b"1..2").is_err());
        assert!(text_decode(N, b"1. ").is_err());
        assert!(text_decode(N, b".5").is_ok());
        assert!(text_decode(N, b"12a").is_err());
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
            Ok(TypedValue::BigDecimal("1.23".into()))
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
