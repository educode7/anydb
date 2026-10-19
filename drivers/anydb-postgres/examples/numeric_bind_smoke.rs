//! Numeric BIND smoke against a REAL postgres — `cargo run -p anydb-postgres
//! --example numeric_bind_smoke`.
//!
//! Default target `postgres://postgres:anydb@localhost:5433/postgres`
//! (container `anydb-postgres`, postgres:16-alpine). Every probe asserts:
//! the client encodes `BigDecimal` text into the numeric external binary
//! form, the REAL server decodes it and echoes it back (`SELECT $1`), and
//! the typed reply must render the canonical plain expansion of the input
//! (display scale preserved, negative zero normalized, scientific text
//! folded). This is the full client-encode -> server-decode loop; any
//! wrong group, weight or dscale would surface as a different render.

use anydb_postgres::PostgresDriver;
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
        container_id: "numeric-bind-smoke".to_owned(),
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

    // Roundtrip battery: our binary bytes in, the server's judgment out.
    let battery: &[(&str, &str)] = &[
        ("123.456", "123.456"),
        ("1.5", "1.5"),
        ("1.500", "1.500"),
        ("0.005", "0.005"),
        ("150", "150"),
        ("150.5", "150.5"),
        ("-150.5", "-150.5"),
        ("1234", "1234"),
        ("15000", "15000"),
        (".5", "0.5"),
        ("0", "0"),
        ("-0.0", "0.0"), // strip_var normalizes the sign
        ("1e-7", "0.0000001"),
        ("1e7", "10000000"),
        ("1.5e3", "1500"),
        ("1e-100", "0.0000...1" /* expanded below */),
        ("NaN", "NaN"),
        ("Infinity", "Infinity"),
        ("-Infinity", "-Infinity"),
        (
            "99999999999999999999999999999999999999.99999999",
            "99999999999999999999999999999999999999.99999999",
        ),
    ];
    for &(text, expected) in battery {
        let result = source
            .execute_typed_statement("SELECT $1", &[QueryParameter::BigDecimal(text.to_owned())])
            .await
            .unwrap_or_else(|error| panic!("bind '{text}' failed: {error}"));
        let Some(TypedValue::BigDecimal(rendered)) = result.rows[0][0].clone() else {
            panic!("'{text}': typed column missing");
        };
        if text == "1e-100" {
            // 1e-100 expands to 100 fraction digits; assert the shape.
            let mut expected = "0.".to_owned();
            expected.push_str(&"0".repeat(99));
            expected.push('1');
            assert_eq!(rendered, expected, "render of '{text}'");
            println!("== {text:>54} -> 0.<99 zeros>1 ✓");
            continue;
        }
        assert_eq!(
            rendered, expected,
            "server render of '{text}' must be the canonical expansion"
        );
        println!("== {text:>54} -> {rendered} ✓");
    }

    // Server-side numeric equality: scale-insensitive by value.
    let equality = source
        .execute_typed_statement(
            "SELECT 1 WHERE $1 = 0.0050",
            &[QueryParameter::BigDecimal("0.005".to_owned())],
        )
        .await
        .expect("equality probe");
    assert_eq!(equality.rows.len(), 1, "0.005 must equal 0.0050 by value");
    println!("== SELECT 1 WHERE $1 = 0.0050 with $1 = 0.005 -> 1 row ✓");

    // Invalid decimal text is a bind-time protocol error BEFORE the wire:
    // the failed statement must not poison the connection.
    let invalid = source
        .execute_typed_statement(
            "SELECT $1",
            &[QueryParameter::BigDecimal("1.5x".to_owned())],
        )
        .await;
    let error = match invalid {
        Err(error) => error,
        Ok(_) => panic!("'1.5x' must fail at bind time"),
    };
    assert!(
        error.to_string().contains("invalid decimal text"),
        "named bind-time error, got: {error}"
    );
    println!("== '1.5x' -> bind-time error: {error}");
    let reusable = source
        .execute_typed_statement("SELECT $1", &[QueryParameter::BigDecimal("42".to_owned())])
        .await
        .expect("connection stays reusable");
    assert_eq!(
        reusable.rows[0][0].as_ref().map(|v| v.to_string()),
        Some("42".to_owned())
    );
    println!("== SELECT $1 with 42 after the failure -> 42 ✓");

    source.close().await;
    println!("== done: every bind round-tripped through the live server");
}
