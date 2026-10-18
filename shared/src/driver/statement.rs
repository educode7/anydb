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
