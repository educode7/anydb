//! Smoke demo against a REAL mongod — `cargo run -p anydb-mongo --example smoke`.
//!
//! Accepts either target form the platform contract supports:
//!   * full connection string: `mongodb://localhost:27017/vuce-landingz`
//!   * the host-port-database form: empty target + the `host` / `port`
//!     / `database` properties
//!
//! Default: `mongodb://localhost:27017/vuce-landingz`; the demo only
//! READS. Idempotent seed (any mongod reachable on that URI):
//!
//! ```text
//! docker exec anydb-mongo mongosh --quiet --eval "
//! let db = db.getSiblingDB('vuce-landingz'); db.anydb_smoke.drop();
//! db.anydb_smoke.insertMany([
//!   {n:1,tag:'a',flag:true},{n:2,tag:'a',flag:false},
//!   {n:3,tag:'b',flag:true},{n:4,tag:'b',flag:false},
//!   {n:5,tag:'c',flag:true},{n:6,tag:'c',flag:false},
//!   {n:7,tag:'dec',flag:true,price:NumberDecimal('123.456'),ts:Timestamp(1735689600,5)},
//!   {n:8,tag:'dec',flag:false,price:NumberDecimal('NaN'),ts:Timestamp(1,1)}]);"
//! ```

use anydb_mongo::MongoDriver;
use anydb_shared::driver::spi::{DataSource as _, DataSourceMetadata, OpenRequest};
use anydb_shared::driver::statement::QueryParameter;

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "mongodb://localhost:27017/vuce-landingz".to_owned());
    println!("target: {target}");

    let driver = MongoDriver::new();
    let request = OpenRequest {
        container_id: "smoke".to_owned(),
        target,
        // The host-port-database alternative (kept commented): properties
        // map([("host", "..."), ("port", "27017"), ("database", "...")]).
        properties: Default::default(),
    };
    let source = driver
        .open_wire_data_source(request)
        .await
        .expect("open data source");
    let DataSourceMetadata {
        product_name,
        product_version,
        driver_name,
    } = source.metadata();
    println!("{product_name} {product_version} via {driver_name}");

    source.ping().await.expect("ping");
    println!("ping ok");

    // 1) One-shot typed find (whole collection, single drained batch).
    let all = source
        .execute_statement_typed("find anydb_smoke", &[])
        .await
        .expect("typed find");
    print_result(&all, "find anydb_smoke");

    // 2) Filter + typed parameters (client-side BSON binding).
    let filtered = source
        .execute_statement_typed(
            "find anydb_smoke with n > ? and tag = ?",
            &[
                QueryParameter::Integer(2),
                QueryParameter::Text("b".to_owned()),
            ],
        )
        .await
        .expect("filtered find");
    print_result(&filtered, "find anydb_smoke with n > ? and tag = ?");

    // 2b) Or + parenthesized groups: `and` binds tighter, so this is
    // {n in [1,3]} or {tag = 'dec'} server-side.
    let combined = source
        .execute_statement_typed("find anydb_smoke with (n in (1, 3) or tag = 'dec')", &[])
        .await
        .expect("or-filtered find");
    print_result(
        &combined,
        "find anydb_smoke with (n in (1, 3) or tag = 'dec')",
    );

    // 2c) Unary `not`: group negation as `$nor`, a negated `in` as
    // `{n: {$not: {$in: [...]}}}`, and a `$not` slot merged beside a
    // positive equality. All applied server-side by the real mongod.
    let negated = source
        .execute_statement_typed("find anydb_smoke with not (n > 5 or tag = 'a')", &[])
        .await
        .expect("not group find");
    print_result(&negated, "find anydb_smoke with not (n > 5 or tag = 'a')");

    let negated_in = source
        .execute_statement_typed("find anydb_smoke with not n in (1, 2, 3, 4)", &[])
        .await
        .expect("not in find");
    print_result(&negated_in, "find anydb_smoke with not n in (1, 2, 3, 4)");

    let negated_slot = source
        .execute_statement_typed("find anydb_smoke with flag = true and not tag = 'a'", &[])
        .await
        .expect("not slot find");
    print_result(
        &negated_slot,
        "find anydb_smoke with flag = true and not tag = 'a'",
    );

    // 3) Cursor paging: batches of two while the cursor id stays open.
    let mut page = source
        .query_page_start(
            "find anydb_smoke with flag = ?",
            &[QueryParameter::Boolean(true)],
            2,
        )
        .await
        .expect("paged find");
    let mut batch = 1;
    loop {
        println!(
            "-- batch {batch}: {} row(s), suspended: {}",
            page.result.rows.len(),
            page.suspended
        );
        print_rows(page.result.columns.clone(), &page.result.rows);
        if !page.suspended {
            println!(
                "-- drained: total {} ({} batch(es))",
                page.result.affected_rows.unwrap_or_default(),
                batch
            );
            break;
        }
        page = source.query_page_continue().await.expect("getMore");
        batch += 1;
    }

    source.close().await;
    println!("smoke ok");
}

/// Renders one typed statement result the way a UI would: column names
/// plus the platform `TypedValue` display (NULL as `null`).
fn print_result(result: &anydb_shared::driver::statement::TypedStatementResult, label: &str) {
    println!("== {label}");
    if let Some(tag) = &result.command_tag {
        println!(
            "   tag: {tag} (affected {})",
            result.affected_rows.unwrap_or_default()
        );
    }
    print_rows(result.columns.clone(), &result.rows);
}

fn print_rows(
    columns: Vec<String>,
    rows: &[Vec<Option<anydb_shared::driver::statement::TypedValue>>],
) {
    println!("   columns: {}", columns.join(", "));
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .map(|cell| match cell {
                Some(value) => value.to_string(),
                None => "null".to_owned(),
            })
            .collect();
        println!("   | {}", cells.join(" | "));
    }
}
