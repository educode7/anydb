//! SPI transaction-control smoke against a REAL postgres — `cargo run -p
//! anydb-postgres --example transactions_smoke`.
//!
//! Default target `postgres://postgres:anydb@localhost:5433/postgres`
//! (container `anydb-postgres`, postgres:16-alpine). Proves through the
//! shared `DataSource` SPI that `begin`/`commit`/`rollback` carry real
//! atomicity over the live wire (not just command tags):
//!
//! 1. A temp table (session-scoped) seeded by a committed transaction.
//! 2. A rolled back transaction leaves zero rows (discard proof).
//! 3. A statement failing inside a transaction (22012) aborts it; the
//!    ROLLBACK normalizes state and discards its writes; execution
//!    keeps working (the `InvalidateScope::Transactions` analog).
//! 4. BigDecimal (OID 1700 binary) still binds across the flow.

use anydb_postgres::PostgresDriver;
use anydb_shared::ConnectionError;
use anydb_shared::driver::spi::{DataSource as _, DataSourceMetadata, OpenRequest};
use anydb_shared::driver::statement::{QueryParameter, TypedValue};

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "postgres://postgres:anydb@localhost:5433/postgres".to_owned());
    println!("target: {target}");

    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "txn-smoke".to_owned(),
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

    // Session temp table: no schema cleanup needed after the run.
    source
        .execute_typed_statement("CREATE TEMP TABLE anydb_spi_txn (v numeric)", &[])
        .await
        .expect("temp table");

    // Seed: one committed transaction.
    source.begin_transaction().await.expect("BEGIN");
    source
        .execute_typed_statement(
            "INSERT INTO anydb_spi_txn VALUES ($1)",
            &[QueryParameter::BigDecimal("9.5".to_owned())],
        )
        .await
        .expect("committed insert");
    source.commit_transaction().await.expect("COMMIT");
    assert_eq!(count(&source).await, 1, "COMMIT must persist");
    println!("== begin + INSERT 9.5 + commit -> 1 row ✓");

    // Discard proof: rolled back writes vanish.
    source.begin_transaction().await.expect("BEGIN");
    source
        .execute_typed_statement(
            "INSERT INTO anydb_spi_txn VALUES ($1)",
            &[QueryParameter::BigDecimal("42".to_owned())],
        )
        .await
        .expect("rolled back insert");
    source.rollback_transaction().await.expect("ROLLBACK");
    assert_eq!(count(&source).await, 1, "ROLLBACK must discard");
    println!("== begin + INSERT 42 + rollback -> still 1 row ✓");

    // Aborted transaction: the failing statement poisons the txn; the
    // ROLLBACK normalizes state to idle and keeps execution reusable.
    source.begin_transaction().await.expect("BEGIN");
    source
        .execute_typed_statement(
            "INSERT INTO anydb_spi_txn VALUES ($1)",
            &[QueryParameter::BigDecimal("1.23".to_owned())],
        )
        .await
        .expect("insert before the failure");
    let error = source
        .execute_typed_statement("SELECT 1/0", &[])
        .await
        .expect_err("division by zero must fail inside the txn");
    assert!(
        matches!(
            error,
            ConnectionError::ExecutionFailed { ref sqlstate, .. } if sqlstate.as_deref() == Some("22012")
        ),
        "SQLSTATE surfaced: {error}"
    );
    println!("== 1/0 inside the txn -> {error}");
    source.rollback_transaction().await.expect("ROLLBACK");
    assert_eq!(count(&source).await, 1, "aborted txn discarded");
    let reusable = source
        .execute_typed_statement("SELECT 40 + 2", &[])
        .await
        .expect("execution after the aborted txn");
    assert_eq!(reusable.rows[0][0].clone(), Some(TypedValue::Int4(42)));
    println!("== rollback after the abort -> 40+2 = 42 ✓");

    source.close().await;
    println!("== done: begin/commit/rollback carry real atomicity");
}

/// Rows in the temp table (int count decoded through the typed catalog).
async fn count(source: &anydb_postgres::WireDataSource) -> i64 {
    let result = source
        .execute_typed_statement("SELECT count(*)::int FROM anydb_spi_txn", &[])
        .await
        .expect("count query");
    match result.rows[0][0].clone() {
        Some(TypedValue::Int4(value)) => i64::from(value),
        other => panic!("count: unexpected {other:?}"),
    }
}
