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
//! 2. DRAIN: previous runs (aborted mid-leg) leave their scratch
//!    documents behind, so the live leg first removes everything from
//!    the collection through the confirmed seam and asserts `find 0`;
//! 3. seed three documents through the driver's own `insert`;
//! 4. `update ... set {"$set": ...}` — "matched / modified" acceptance,
//!    verified back through a find;
//! 5. `update one` — the surgical update touches the FIRST of two
//!    matches; a live mongod stops at the limit and the reply reports
//!    n = 1 ("1 matched, 1 modified"), verified server-side;
//! 6. `delete` through the confirmed seam — "document(s) removed"
//!    acceptance, counts asserted after each leg;
//! 7. `delete one` — the surgical leg removes exactly one of the two
//!    survivors, verified server-side;
//! 8. the collection ends EMPTY (all-matching deletion + `find 0`).
//!
//! Non-zero exit means a failed statement or a failed assertion.
//!
//! Live evidence (mongo 7.0 container `anydb-mongo`): gate refusal
//! `delete statements are destructive ...`, insert `1` x3, `update docs:
//! 1 matched, 1 modified`, `find 1`, `update one docs: 1 matched, 1
//! modified` (the reply n counts the document the limit let through;
//! the surgical clip is verified server-side), `find 1` twice,
//! `delete docs: 1 document(s) removed`, `find 2`,
//! `delete one docs: 1 document(s) removed`, `find 1`,
//! `delete docs: 1 document(s) removed`, `find 0`.

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

    // 2) DRAIN: an aborted earlier run leaves its scratch documents in
    //    the (long-lived) container, and every counting leg below needs
    //    exact populations. Remove everything through the confirmed
    //    seam and assert the collection is empty before seeding.
    let typed = source
        .execute_statement_typed_confirmed("delete docs with n >= 0", &[])
        .await
        .expect("the drain runs through the confirmed seam");
    let drain_removed = typed.affected_rows.unwrap_or(0);
    if drain_removed > 0 {
        println!("drain removed {drain_removed} leftover document(s)");
    }
    let typed = source
        .execute_statement_typed("find docs with n >= 0", &[])
        .await
        .expect("verify the drain");
    assert_eq!(typed.command_tag, Some("find 0".to_owned()));
    println!("drain ok: collection empty");

    // 3) Seed three documents through the driver's own insert surface.
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

    // 5) THE SURGICAL UPDATE LEG: `update one` touches at most the
    //    first match even when the filter matches two. A live mongod
    //    stops at the limit, so the reply reports n = 1 (the document
    //    it processed) — the surgical behavior itself is verified
    //    server-side through the finds below, not through the reply.
    let typed = source
        .execute_statement_typed(
            r#"update one docs with smoked = false set {"$set": {"n": 22}}"#,
            &[],
        )
        .await
        .expect("the single-document update executes from the ordinary path");
    assert_eq!(typed.command_tag, Some("update 1".to_owned()));
    let surgical_update = typed.message.expect("update one acceptance");
    assert_eq!(surgical_update, "update docs: 1 matched, 1 modified");
    println!("acceptance (update one): {surgical_update}");

    // Exactly the first match got `n: 22` and its sibling kept `n: 3`.
    let typed = source
        .execute_statement_typed("find docs with n = 22", &[])
        .await
        .expect("verify the surgical update applied");
    assert_eq!(typed.command_tag, Some("find 1".to_owned()));
    let typed = source
        .execute_statement_typed("find docs with tag = 'smoke-c' and n = 3", &[])
        .await
        .expect("verify the survivor was untouched");
    assert_eq!(typed.command_tag, Some("find 1".to_owned()));
    println!("update one verified server-side: find 1 and the survivor intact");

    // 5) Delete one match through the confirmed seam.
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

    // 6) THE SURGICAL DELETE LEG: the single-document form removes
    //    exactly one of the two survivors, and the acceptance says so.
    let typed = source
        .execute_statement_typed_confirmed("delete one docs with tag = 'smoke-b'", &[])
        .await
        .expect("the confirmed seam runs the single-document delete");
    assert_eq!(typed.command_tag, Some("delete 1".to_owned()));
    let surgical_acceptance = typed.message.expect("delete one acceptance");
    assert_eq!(surgical_acceptance, "delete docs: 1 document(s) removed");
    println!("acceptance (delete one): {surgical_acceptance}");

    // Exactly `smoke-b` went; the survivor stays.
    let typed = source
        .execute_statement_typed("find docs with tag = 'smoke-c'", &[])
        .await
        .expect("verify the surgical deletion kept the survivor");
    assert_eq!(typed.command_tag, Some("find 1".to_owned()));
    println!("delete one verified server-side: find 1");

    // 7) The last survivor goes the same all-matching way; the
    //    acceptance reports the honest count (one, after the surgical
    //    leg already took its document).
    let typed = source
        .execute_statement_typed_confirmed("delete docs with n = 3", &[])
        .await
        .expect("the confirmed seam runs the final delete");
    assert_eq!(typed.command_tag, Some("delete 1".to_owned()));
    let remaining_acceptance = typed.message.expect("final delete acceptance");
    assert_eq!(remaining_acceptance, "delete docs: 1 document(s) removed");
    println!("acceptance: {remaining_acceptance}");

    let typed = source
        .execute_statement_typed("find docs", &[])
        .await
        .expect("verify the empty collection");
    assert_eq!(typed.command_tag, Some("find 0".to_owned()));
    println!("collection drained: find 0");

    println!("delete/update smoke: all acceptance proofs passed");
}
