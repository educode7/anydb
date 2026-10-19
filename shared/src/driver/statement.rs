//! Statement execution contract shared by drivers (DBeaver
//! `JDBCPreparedStatement` analog at the SPI level).

/// Driver-neutral parameter for prepared statements. Drivers map each
/// variant to their native wire encoding (Postgres: binary format plus a
/// declared type OID; see anydb-postgres `protocol::param_*`).
///
/// `Integer` maps to the driver's widest signed integer (Postgres: `int8`),
/// `Float` to the widest binary float (`float8`); narrower parameter columns
/// accept them through the usual server-side coercions.
#[derive(Debug, Clone, PartialEq)]
pub enum QueryParameter {
    /// NULL: drivers send a null-length value and let the server infer the
    /// type from the statement context.
    Null,
    Boolean(bool),
    Integer(i64),
    Float(f64),
    Text(String),
    /// Opaque driver-native bytes (Postgres: `bytea`).
    Binary(Vec<u8>),
}

/// Result of one prepared-statement execution. Values are text-format
/// strings (NULL is `None`), so the SPI stays type-decoding-free; typed
/// decoding belongs to upper layers once catalogs are in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    /// Last `CommandComplete` tag verbatim (`UPDATE 3`, `SELECT 2`, ...).
    pub command_tag: Option<String>,
    /// Trailing batch count of the tag when it is a plain number
    /// (`UPDATE 3` -> 3, `INSERT 0 1` -> 1, `BEGIN` -> None).
    pub affected_rows: Option<i64>,
}

/// Result of one prepared-statement execution with typed values applied by
/// the driver's binary / text type catalog (DBeaver `TypedValue` rendering
/// analog). Driver-neutral: columns carry names only; richer driver-specific
/// metadata (Postgres type OIDs) stays in the driver's own typed layer.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedStatementResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<TypedValue>>>,
    /// Last `CommandComplete` tag verbatim (`UPDATE 3`, `SELECT 2`, ...).
    pub command_tag: Option<String>,
    /// Trailing batch count of the tag when it is a plain number
    /// (`UPDATE 3` -> 3, `INSERT 0 1` -> 1, `BEGIN` -> None).
    pub affected_rows: Option<i64>,
}

/// A typed result value produced by a driver's binary / text type catalog
/// (DBeaver `TypedValue` analog). One variant per supported native type;
/// drivers keep narrower types (`int2`/`int4`, `float4`/`float8`) distinct
/// so callers can see the declared column type.
///
/// `Display` renders platform-friendly text: booleans as `true`/`false`
/// (not Postgres' `t`/`f`), bytea with the `\x` hex prefix (Postgres
/// canonical), and non-finite floats as Postgres canonical text
/// (`NaN`, `Infinity`, `-Infinity`).
#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    Boolean(bool),
    Int2(i16),
    Int4(i32),
    Int8(i64),
    Float4(f32),
    Float8(f64),
    Text(String),
    /// Arbitrary-precision decimal carried as canonical decimal TEXT
    /// (the DBeaver `BigDecimal` analog): mongo `decimal128` values,
    /// and Postgres `numeric` when the typed surface adopts it. Text is
    /// the lossless carrier — 34-digit significands survive `Float8`
    /// roundings only by never going through it.
    BigDecimal(String),
    /// Opaque driver-native bytes (Postgres: `bytea`).
    Bytea(Vec<u8>),
}

impl std::fmt::Display for TypedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Boolean(value) => write!(f, "{}", if *value { "true" } else { "false" }),
            Self::Int2(value) => write!(f, "{value}"),
            Self::Int4(value) => write!(f, "{value}"),
            Self::Int8(value) => write!(f, "{value}"),
            Self::Float4(value) => write!(f, "{}", float_text(*value as f64)),
            Self::Float8(value) => write!(f, "{}", float_text(*value)),
            Self::Text(value) => write!(f, "{value}"),
            Self::BigDecimal(value) => write!(f, "{value}"),
            Self::Bytea(bytes) => {
                write!(f, "\\x")?;
                for byte in bytes {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// Non-finite floats render as Postgres canonical text; finite floats use
/// the shortest Rust representation (`4` for `4.0`), matching how the
/// server prints them.
fn float_text(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value == f64::INFINITY {
        "Infinity".to_owned()
    } else if value == f64::NEG_INFINITY {
        "-Infinity".to_owned()
    } else {
        value.to_string()
    }
}
