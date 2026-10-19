//! Portal paging smoke against a REAL postgres — `cargo run
//! -p anydb-postgres --example paging_smoke`.
//!
//! Default target `postgres://postgres:anydb@localhost:5433/postgres`
//! (container `anydb-postgres`, postgres:16-alpine). Finds the pending
//! multi-batch behaviors the fake backends cannot adjudicate:
//!
//! - real multi-batch drain over PortalSuspended (typed numeric
//!   decoding riding every batch),
//! - abandoning a suspended page with a one-shot statement,
//! - a mid-batch runtime error leaving NO stale portal state behind.

use anydb_postgres::PostgresDriver;
use anydb_shared::ConnectionError;
use anydb_shared::driver::spi::{DataSource as _, DataSourceMetadata, OpenRequest};

fn print_page(label: &str, index: usize, page: &anydb_postgres::protocol::TypedPage) {
    println!(
        "== {label} batch #{index} ({} rows)",
        page.result.rows.len()
    );
    for row in &page.result.rows {
        let cells: Vec<String> = row
            .iter()
            .map(|cell| match cell {
                Some(value) => format!("{value:?}"),
                None => "NULL".to_owned(),
            })
            .collect();
        println!("   | {}", cells.join(" | "));
    }
    if let Some(tag) = &page.result.command_tag {
        println!("   | tag: {tag}");
    }
}

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "postgres://postgres:anydb@localhost:5433/postgres".to_owned());
    println!("target: {target}");

    let driver = PostgresDriver::new();
    let request = OpenRequest {
        container_id: "paging-smoke".to_owned(),
        target,
        properties: Default::default(),
    };
    let source = driver
        .open_wire_data_source(request)
        .await
        .expect("open data source");
    let DataSourceMetadata { product_name, .. } = source.metadata();
    println!("== {product_name}");

    // 1) Real multi-batch drain: 14 rows in batches of three; the
    //    numeric column keeps binary decoding on every page.
    let series = "SELECT n, (n::numeric * 1.05)::numeric(38, 2) \
                  FROM generate_series(1, 14) AS n ORDER BY n";
    let mut page = source
        .query_page_start(series, &[], 3)
        .await
        .expect("page start");
    print_page(series, 1, &page);
    assert!(page.suspended, "batches of three must suspend for 14 rows");
    let mut batch = 2usize;
    while page.suspended {
        page = source.query_page_continue(3).await.expect("next batch");
        print_page(series, batch, &page);
        batch += 1;
    }
    // Wire semantics the real server teaches: the final CommandComplete
    // tag counts the rows of the LAST continuation only (`SELECT 2`),
    // never the whole portal.
    assert_eq!(
        page.result.affected_rows,
        Some(2),
        "final tag counts the last continuation"
    );

    // 2) A one-shot statement abandons a half-open page: its own Sync
    //    ends the implicit transaction, the portal dies server-side,
    //    and the local paging state must not lie afterwards.
    let abandoned = source
        .query_page_start("SELECT n FROM generate_series(1, 8) AS n", &[], 4)
        .await
        .expect("abandoned page start");
    print_page("abandoned flow", 1, &abandoned);
    assert!(abandoned.suspended);
    let one_shot = source
        .execute_typed_statement("SELECT count(*) FROM generate_series(1, 8)", &[])
        .await
        .expect("one-shot while a page is suspended");
    println!("== one-shot mid-page: count = {:?}", one_shot.rows[0][0]);
    let stale = match source.query_page_continue(4).await {
        Err(ConnectionError::Protocol(message)) if message == "no suspended portal" => {
            "no suspended portal (clean refusal)"
        }
        other => unreachable!("expected the clean stale refusal, got {other:?}"),
    };
    println!("== continue after one-shot abandon: {stale}");

    // 3) A fresh page start right after the abandonment rebuilds the
    //    full flow (the superfluous Sync of the dead portal is drained).
    let rebuilt = source
        .query_page_start("SELECT n FROM generate_series(1, 5) AS n", &[], 2)
        .await
        .expect("rebuilt page start");
    print_page("rebuilt flow", 1, &rebuilt);
    assert!(rebuilt.suspended);

    // 4) Mid-batch error: rows stream until the failing cast, the
    //    implicit transaction aborts and takes the portal with it —
    //    continuing must fail locally, recovery must just work.
    let faulty = "SELECT x::numeric FROM (VALUES ('1'), ('2'), ('oops')) AS t(x)";
    let half = source
        .query_page_start(faulty, &[], 2)
        .await
        .expect("faulty page start");
    print_page(faulty, 1, &half);
    assert!(half.suspended, "two of three rows stream before the cast");
    let failure = source
        .query_page_continue(3)
        .await
        .expect_err("the failing cast surfaces on the continuation");
    println!("== mid-batch error: {failure}");
    match source.query_page_continue(3).await {
        Err(ConnectionError::Protocol(message)) if message == "no suspended portal" => {
            println!("== the aborted transaction left NO stale portal");
        }
        other => panic!("expected the clean disposal, got {other:?}"),
    }
    // Boundary the real server teaches: with max_rows EQUAL to the
    // remaining rows, postgres still suspends (it stops at the last
    // row without one extra look); the next continuation returns zero
    // rows with the closing tag.
    let mut recovered = source
        .query_page_start("SELECT n FROM generate_series(1, 5) AS n", &[], 5)
        .await
        .expect("recovery page after the error");
    print_page("recovered flow", 1, &recovered);
    assert_eq!(recovered.result.rows.len(), 5);
    let mut batch = 2usize;
    while recovered.suspended {
        recovered = source.query_page_continue(5).await.expect("boundary batch");
        print_page("recovered flow", batch, &recovered);
        batch += 1;
    }
    assert_eq!(
        recovered.result.command_tag.as_deref(),
        Some("SELECT 0"),
        "the boundary continuation contributes no rows"
    );

    // 5) limit = 0 degenerates to fetch-all (never suspends).
    let whole = source
        .query_page_start("SELECT n FROM generate_series(1, 14) AS n", &[], 0)
        .await
        .expect("fetch-all page");
    assert!(!whole.suspended);
    assert_eq!(whole.result.rows.len(), 14);
    println!(
        "== limit=0 fetch-all: {} rows, no suspension",
        whole.result.rows.len()
    );

    println!("== paging smoke OK");
}
