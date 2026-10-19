//! Numeric smoke against a REAL postgres — `cargo run -p anydb-postgres
//! --example numeric_smoke`.
//!
//! Default target `postgres://postgres:anydb@localhost:5433/postgres`
//! (container `anydb-postgres`, postgres:16-alpine). Idempotent seed:
//!
//! ```text
//! docker exec anydb-postgres psql -U postgres -c "DROP TABLE IF EXISTS
//!   anydb_numeric; CREATE TABLE anydb_numeric (id int, v numeric);
//!   INSERT INTO anydb_numeric VALUES
//!     (1, 123.456), (2, '1.5'::numeric(10,3)), (3, 0.005),
//!     (4, '1e-7'::numeric), (5, -150.5), (6, 'NaN'::numeric),
//!     (7, 'Infinity'::numeric), (8, '-Infinity'::numeric),
//!     (9, 1234567890123456789012345678901234), (10, '1e-100'::numeric),
//!     (11, '-0.0'::numeric), (12, 0), (13, 15000),
//!     (14, '99999999999999999999999999999999999999.99999999'::numeric);"
//! ```

use anydb_postgres::PostgresDriver;
use anydb_shared::driver::spi::{DataSource as _, DataSourceMetadata, OpenRequest};

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "postgres://postgres:anydb@localhost:5433/postgres".to_owned());
    println!("target: {target}");

    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "numeric-smoke".to_owned(),
        target,
        properties: Default::default(),
    };
    let source = driver
        .open_wire_data_source(request)
        .await
        .expect("open data source");
    let DataSourceMetadata {
        product_name,
        product_version,
        ..
    } = source.metadata();
    println!("== {product_name} {product_version}");

    let result = source
        .execute_typed_statement("SELECT id, v FROM anydb_numeric ORDER BY id", &[])
        .await
        .expect("typed query");
    println!("== SELECT id, v FROM anydb_numeric ORDER BY id");
    for row in &result.rows {
        let id = match &row[0] {
            Some(value) => value.to_string(),
            None => "NULL".to_owned(),
        };
        let v = match &row[1] {
            Some(value) => format!("{value:?}"),
            None => "NULL".to_owned(),
        };
        println!("   | id={id} v={v}");
    }

    // Negative zero evidence through the wire: what the server sends.
    let sign_zero = source
        .execute_typed_statement("SELECT '-0.0'::numeric, '-0'::numeric", &[])
        .await
        .expect("negative zero probe");
    for row in &sign_zero.rows {
        println!("== negative-zero probe: {:?}", &row[..]);
    }

    // Aggregates exercise computed numerics (division produces repeating
    // decimals capped by the chosen scale).
    let division = source
        .execute_typed_statement("SELECT 1::numeric / 3, 10::numeric / 3", &[])
        .await
        .expect("division probe");
    for row in &division.rows {
        println!("== division probe: {:?}", &row[..]);
    }
}
