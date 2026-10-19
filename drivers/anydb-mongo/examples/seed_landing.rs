//! Seeds the VUCE landing `components` collection through the same
//! anydb statement surface everything else uses — no driver-private
//! write path, just `insert <collection> with <json-document>`.
//!
//! ```text
//! cargo run -p anydb-mongo --example seed_landing -- [target] [data-dir]
//! ```
//!
//! * `target` — connection string. Default:
//!   `mongodb://localhost:27017/vuce-landing` (the `anydb-mongo` docker
//!   container; the database name is the one the consumer called
//!   `vuce-landing`).
//! * `data-dir` — directory holding the `group-*.json` documents.
//!   Default: `<crate>/examples/data/vuce-landing`.
//!
//! The collection name `components` is fixed by the consumer
//! (`@Document(value = "components")` in the Spring API), and the
//! documents are `ComponentsEntity` shaped.
//!
//! Flow: read every group file first (an unreadable file inserts
//! nothing), skip the load entirely when the collection already holds
//! documents, insert one statement per group, then prove the load with
//! `find components` and print the `authenticationType` census read
//! back FROM THE SERVER.
//!
//! Re-seeding needs the collection empty (the statement surface has no
//! `delete` yet):
//!
//! ```text
//! docker exec anydb-mongo mongosh --quiet --eval \
//!   "db.getSiblingDB('vuce-landing').components.drop()"
//! ```
//!
//! The group documents are derived from the verbatim upstream payload
//! `aplicaciones.json` by `transform.mjs` in the same directory, which
//! also asserts every `authenticationType` rule it applies.

use std::path::{Path, PathBuf};

use anydb_mongo::MongoDriver;
use anydb_shared::driver::spi::{DataSource as _, OpenRequest};
use anydb_shared::driver::statement::{TypedStatementResult, TypedValue};

/// The consumer's `@Document(value = "components")`.
const COLLECTION: &str = "components";

/// The `authenticationType` values the census counts, as the extended
/// JSON their cells actually contain (embedded documents travel as text
/// with `": "` separators — see `bson::render`), so the closing quote
/// keeps `AUTH1` from matching inside `AUTH1_AUTH2`.
const TYPES: [(&str, &str); 3] = [
    ("AUTH1_AUTH2", "\"authenticationType\": \"AUTH1_AUTH2\""),
    ("AUTH2", "\"authenticationType\": \"AUTH2\""),
    ("AUTH1", "\"authenticationType\": \"AUTH1\""),
];

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "mongodb://localhost:27017/vuce-landing".to_owned());
    let data_dir = std::env::args()
        .nth(2)
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir);

    if let Err(failure) = run(&target, &data_dir).await {
        eprintln!("seed_landing: {failure}");
        std::process::exit(1);
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("data")
        .join("vuce-landing")
}

async fn run(target: &str, data_dir: &Path) -> Result<(), String> {
    println!("target: {target}");
    println!("data:   {}", data_dir.display());

    // Every file is read BEFORE the first insert: a missing or empty
    // group document cannot leave a half-seeded collection behind.
    let documents = load_group_documents(data_dir)?;

    let driver = MongoDriver::new();
    let request = OpenRequest {
        container_id: "seed_landing".to_owned(),
        target: target.to_owned(),
        properties: Default::default(),
    };
    let source = driver
        .open_wire_data_source(request)
        .await
        .map_err(|error| format!("open data source: {error}"))?;
    source
        .ping()
        .await
        .map_err(|error| format!("ping: {error}"))?;

    let existing = source
        .execute_statement_typed(&format!("find {COLLECTION}"), &[])
        .await
        .map_err(|error| format!("preflight find: {error}"))?;
    if !existing.rows.is_empty() {
        println!(
            "{COLLECTION} already holds {} document(s); nothing inserted.",
            existing.rows.len()
        );
        let database = database(target);
        println!(
            "re-seed with: docker exec anydb-mongo mongosh --quiet --eval \"db.getSiblingDB('{database}').{COLLECTION}.drop()\""
        );
        source.close().await;
        return Ok(());
    }

    for (name, text) in &documents {
        let statement = format!("insert {COLLECTION} with {text}");
        let result = source
            .execute_statement_typed(&statement, &[])
            .await
            .map_err(|error| format!("insert from {name}: {error}"))?;
        println!(
            "insert {name} -> {}",
            result.command_tag.as_deref().unwrap_or("no tag")
        );
    }

    let verify = source
        .execute_statement_typed(&format!("find {COLLECTION}"), &[])
        .await
        .map_err(|error| format!("verification find: {error}"))?;
    source.close().await;
    report(&verify, documents.len())
}

/// Reads `group-*.json` sorted by their numeric suffix so the inserts
/// follow the payload's group order whatever the file names look like.
fn load_group_documents(data_dir: &Path) -> Result<Vec<(String, String)>, String> {
    let entries = std::fs::read_dir(data_dir)
        .map_err(|error| format!("read {}: {error}", data_dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                name.to_string_lossy().starts_with("group-")
                    && name.to_string_lossy().ends_with(".json")
            })
        })
        .collect();
    paths.sort_by_key(|path| group_number(path));
    if paths.is_empty() {
        return Err(format!(
            "no group-*.json documents in {}",
            data_dir.display()
        ));
    }
    paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("read {}: {error}", path.display()))?;
            if text.trim().is_empty() {
                return Err(format!("{} is empty", path.display()));
            }
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok((name, text))
        })
        .collect()
}

/// Numeric suffix of `group-<n>.json`; a name without one sorts last.
fn group_number(path: &Path) -> (u64, String) {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let number = name
        .strip_prefix("group-")
        .and_then(|rest| rest.strip_suffix(".json"))
        .and_then(|rest| rest.parse::<u64>().ok())
        .unwrap_or(u64::MAX);
    (number, name)
}

/// The database segment of a `mongodb://.../<database>` target, for
/// the re-seed hint; `admin` when the target carries no path.
fn database(target: &str) -> &str {
    target
        .rsplit_once('/')
        .and_then(|(_, database)| (!database.is_empty()).then_some(database))
        .unwrap_or("admin")
}

/// Prints what came back from the server: tag, row count, and the
/// `authenticationType` census of every group document.
fn report(result: &TypedStatementResult, expected: usize) -> Result<(), String> {
    let tag = result.command_tag.clone().unwrap_or_default();
    if result.rows.len() != expected {
        return Err(format!(
            "expected {expected} document(s) after seeding, find reported {} ({tag})",
            result.rows.len()
        ));
    }
    println!("verify: find {COLLECTION} -> {tag}");
    let Some(components) = result
        .columns
        .iter()
        .position(|column| column == "listComponent")
    else {
        return Err("the verification result has no listComponent column".to_owned());
    };
    let Some(group_column) = result
        .columns
        .iter()
        .position(|column| column == "codeGroup")
    else {
        return Err("the verification result has no codeGroup column".to_owned());
    };
    let mut totals = [0usize; TYPES.len()];
    for row in &result.rows {
        let group = cell(row, group_column).unwrap_or_default();
        let components_json = cell(row, components).unwrap_or_default();
        let census: Vec<String> = TYPES
            .iter()
            .enumerate()
            .map(|(index, (label, needle))| {
                let hits = components_json.matches(needle).count();
                totals[index] += hits;
                format!("{label}={hits}")
            })
            .collect();
        println!(
            "  group {group}: {} component(s) in {} bytes, {}",
            components_json.matches("\"codeComponent\"").count(),
            components_json.len(),
            census.join(" ")
        );
    }
    let summary: Vec<String> = TYPES
        .iter()
        .enumerate()
        .map(|(index, (label, _))| format!("{label}={}", totals[index]))
        .collect();
    println!(
        "  census: {} ({} document(s))",
        summary.join(" "),
        result.rows.len()
    );
    Ok(())
}

/// The text cell of one column, when it is text.
fn cell(row: &[Option<TypedValue>], column: usize) -> Option<String> {
    match row.get(column) {
        Some(Some(TypedValue::Text(text))) => Some(text.clone()),
        _ => None,
    }
}
