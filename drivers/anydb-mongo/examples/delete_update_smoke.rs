//! Live smoke for the mongo DELETE / UPDATE write surface —
//! `cargo run -p anydb-mongo --example delete_update_smoke -- [target]`.
//!
//! Default target `mongodb://localhost:27017/anydb-scrap`: a throwaway
//! database (mongo drops it together with its empty collection), so the
//! `vuce-landing` fixture and the `anydb_smoke` census are never
//! written. Flow, every leg printed with its visible acceptance:
//!
//! 1. the UNCONFIRMED gate: the ordinary typed surface refuses a delete
//!    naming the confirmed seam, client-side;
//! 2. seed three documents through the driver's own `insert`;
//! 3. `update ... set {"$set": ...}` — "matched / modified" acceptance,
//!    verified back through a find;
//! 4. `delete` through the confirmed seam — "document(s) removed"
//!    acceptance, counts asserted after each leg;
//! 5. the collection ends EMPTY (both deletions + verified `find 0`).
//!
//! Non-zero exit means a failed statement or a failed assertion.
//!
//! Live evidence (mongo 7.0 container `anydb-mongo`): gate refusal
//! `delete statements are destructive ...`, `insert 1` x3, `update docs:
//! 1 matched, 1 modified`, `find 1`, `delete docs: 1 document(s)
//! removed`, `find 2`, `delete docs: 2 document(s) removed`, `find 0`.

use anydb_mongo::MongoDriver;
use anydb_shared::driver::spi::{DataSource as _, DataSourceMetadata, OpenRequest};

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "mongodb://localhost:27017/anydb-scrap".to_owned());
    println!("target: {target}");

    let driver = MongoDriver::new();
    let request = OpenRequest {
        container_id: "delete-update-smoke".to_owned(),
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
        driver_name,
    } = source.metadata();
    println!("{product_name} {product_version} via {driver_name}");

    source.ping().await.expect("ping");
    println!("ping ok");

    // 1) The unconfirmed gate: a delete refuses BEFORE any wire bytes
    //    and must name the confirmed seam. The connection is untouched.
    let separator_gate = source
        .execute_statement_typed("delete docs with n = 1", &[])
        .await
        .expect_err("the ordinary typed surface refuses a delete");
    let message = match &separator_gate {
        anydb_shared::ConnectionError::Protocol(message) => message.clone(),
        other => panic!("expected the pre-wire gate refusal, got {other:?}"),
    };
    assert!(
        message.contains("execute_statement_typed_confirmed"),
        "the refusal must name the confirmed seam: {message}"
    );
    println!("separator gate ok: {message}");

    // 2) Seed three documents through the driver's own insert surface.
    for (n, tag) in [(1, "smoke-a"), (2, "smoke-b"), (3, "smoke-c")] {
        let typed = source
            .execute_statement_typed(
                &format!(r#"insert docs with {{"n":{n},"tag":"{tag}","smoked":false}}"#),
                &[],
            )
            .await
            .expect("seed insert");
        assert_eq!(typed.command_tag, Some("insert 1".to_owned()));
        println!("insert {tag} -> {}", typed.command_tag.expect("tag"));
    }

    // 3) Update one match through the operator form (ordinary path).
    let typed = source
        .execute_statement_typed(
            r#"update docs with n = 1 set {"$set": {"smoked": true}}"#,
            &[],
        )
        .await
        .expect("update executes");
    assert_eq!(typed.command_tag, Some("update 1".to_owned()));
    assert_eq!(typed.affected_rows, Some(1));
    let update_acceptance = typed.message.expect("update acceptance");
    assert_eq!(update_acceptance, "update docs: 1 matched, 1 modified");
    println!("acceptance: {update_acceptance}");

    // The modified state is real: the $set applied server-side.
    let typed = source
        .execute_statement_typed("find docs with smoked = true", &[])
        .await
        .expect("verify the update");
    assert_eq!(typed.command_tag, Some("find 1".to_owned()));
    println!("update verified server-side: find 1");

    // 4) Delete one match through the confirmed seam.
    let typed = source
        .execute_statement_typed_confirmed("delete docs with n = 1", &[])
        .await
        .expect("the confirmed seam runs the delete");
    assert_eq!(typed.command_tag, Some("delete 1".to_owned()));
    assert_eq!(typed.affected_rows, Some(1));
    let delete_acceptance = typed.message.expect("delete acceptance");
    assert_eq!(delete_acceptance, "delete docs: 1 document(s) removed");
    println!("acceptance: {delete_acceptance}");

    let typed = source
        .execute_statement_typed("find docs", &[])
        .await
        .expect("verify the deletion");
    assert_eq!(typed.command_tag, Some("find 2".to_owned()));
    println!("delete verified server-side: find 2");

    // 5) The remaining two go the same way; the acceptance says so.
    let typed = source
        .execute_statement_typed_confirmed("delete docs with n = 2 or n = 3", &[])
        .await
        .expect("the confirmed seam runs the second delete");
    assert_eq!(typed.command_tag, Some("delete 2".to_owned()));
    let remaining_acceptance = typed.message.expect("second delete acceptance");
    assert_eq!(remaining_acceptance, "delete docs: 2 document(s) removed");
    println!("acceptance: {remaining_acceptance}");

    let typed = source
        .execute_statement_typed("find docs", &[])
        .await
        .expect("verify the empty collection");
    assert_eq!(typed.command_tag, Some("find 0".to_owned()));
    println!("collection drained: find 0");

    println!("delete/update smoke: all acceptance proofs passed");
}
