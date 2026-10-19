# mongo-delete-update — `delete` / `update` with visible write acceptance

Objective: give `anydb-mongo` the remaining destructive write statements and make a deletion
impossible to fire silently: a pre-execution confirmation seam plus a typed, legible
acceptance in the result.
Branch: `feature/mongo-delete-update` (from `main` @ 64fb876). Delivery strategy: stacked
work-unit commits on the branch (same as mongo-insert-statement; no pull requests; push stays
a human decision). The ~400-line planning heuristic is exceeded for the same reason the insert
vertical recorded: grammar, dispatch, wire and shared result shape are one behavior; splitting
them yields commits that do not compile. Test runner: `cargo test --workspace`
+ gates `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo deny check`.

## Specs

### S7 — `delete one` (iteration 2, after the main delivery)

"Aceptación visible" also for surgical removal: `delete one <collection> with <filter-text>`
compiles to `{ delete: <collection>, deletes: [ { q: <compiled filter>, limit: 1 } ] }` — at
most the FIRST matching document (server order) goes, and the acceptance honestly reports a
zero when nothing matched ("delete docs: 0 document(s) removed" instead of a silent OK).

- The standalone token `one` right after `delete` is RESERVED as the single-document
  modifier, mirroring the filter grammar's reserved leading `not`: a collection literally
  named `one` is not addressable in this surface (`delete one` alone, or `delete one` with a
  filter craving a collection, answer the `delete one` form hint before any wire bytes).
- Everything else keeps the iteration-1 contract: filter required, `?` parameters bind in
  the compiled filter, execution only through `execute_statement_typed_confirmed`,
  `writeErrors` and missing counts surface as failures, tag stays `delete <n>`, and the
  plain all-matching `delete <collection> with <filter>` is byte-identical to before.

### S8 — live smoke leg for the single-document form

The existing live smoke gains a surgical leg between the all-matching deletions: after the
first removal (2 documents remain), `delete one docs with tag = 'smoke-b'` removes exactly
one and `find` shows both the survivor and the modified state; the final all-matching
deletion then drains the throwaway collection.

### S1 — statement surface accepts `delete` and `update`

`parse_statement` accepts exactly four statement forms: the existing
`find <collection> [with <filter-text>]` and `insert <collection> with <json-document>`,
plus the new `delete <collection> with <filter-text>` and
`update <collection> with <filter-text> set <json-document>`.

- `delete` **requires** the `with` clause: a filter-less delete (match-everything) is a
  `Protocol` error before any wire round-trip, named "delete statements are
  'delete <collection> with <filter>'". SQL-familiar shapes stay: the filter grammar compiles
  with `?` parameter binding exactly like `find`.
- `update` splits on the first whitespace-standalone `set` token that is OUTSIDE both quote
  kinds (the grammar supports single and double quoted strings with doubled-quote escapes), so
  a filter value like `'my set version'` never splits the statement. Quote-aware scanning is
  client-side only; the split points are byte offsets into the raw SQL.
- The text after `set` is a strict JSON object parsed by the existing `document.rs` parser —
  it is mongo's update spec (`u`) **verbatim**: an operator document (`{"$set": {...}}`)
  applies fields to the matches; a plain document replaces the matches wholesale. The driver
  applies no wrapping and no interpretation.
- Collection name rules are shared with the existing surface (no leading '$').
- Arity mirrors `find`: parameters bind into the filter only; wrong arity is the existing
  filter-arithmetic protocol error. The parsed update document binds nothing (like insert).
- The "unsupported statement" hint now names all four forms; every pre-existing `find` and
  `insert` statement string, filter, error message and behavior is unchanged.

### S2 — the delete confirmation seam (pre-execution acceptance)

- `shared::driver::spi::DataSource` gains one default method:
  `execute_statement_typed_confirmed(sql, params)`. The default delegates to the ordinary
  `execute_statement_typed` (platform-wide, drivers without a confirmation seam degrade
  gracefully; the shape mirrors the transaction-control trio).
- `anydb-postgres` overrides nothing: its default delegation is its behavior.
- `anydb-mongo` ordinary execution (`execute_statement_typed`, and therefore the text-shape
  `execute_statement`) **refuses** a delete with a clear `Protocol` error naming the confirmed
  seam, raised client-side before the connection lock and before any wire bytes: everything
  else dispatches identically to the ordinary path. The confirmed override dispatches
  find / insert / delete / update.
- The update statement is reachable from the ordinary path (the user scoped the gate to
  delete); nothing here rejects it.

### S3 — `delete` executes the mongo `delete` command with a visible acceptance

- Wire command: `{ delete: <collection>, deletes: [ { q: <compiled filter>, limit: 0 } ], $db }`
  through the single round-trip `command()` path. `limit: 0` is SQL DELETE semantics — every
  matching document goes, and this is the surface's only delete form.
- Reply handling reuses the insert's contract: `writeErrors` (which accompany `ok: 1`) land
  first as a parsed command error; a missing or non-count `n` is a protocol error, never a
  silent zero. The writeErrors walker and the counter generalization carry the command context
  in their message text.
- Result: `columns: []`, `rows: []`, `command_tag: Some("delete <n>")`,
  `affected_rows: Some(n)`, and the new visible acceptance
  `message: Some("delete <collection>: <n> document(s) removed")`.

### S4 — `update` executes the mongo `update` command with a visible acceptance

- Wire command:
  `{ update: <collection>, updates: [ { q, u, upsert: false, multi: true } ], $db }`.
  `multi: true` (SQL UPDATE semantics — every match is touched) with
  `upsert: false` (no filter miss mints documents). Recorded surface decision at L4: the
  sibling insert-then-acceptance statements keep one consistent default of "all matching".
- Reply: `n` (matched) and `nModified` (modified) with the same count-shape tolerance
  (Int32 / Int64 / Double), `writeErrors` first as usual.
- Result: `command_tag: Some("update <nModified>")`, `affected_rows: Some(nModified)`,
  `message: Some("update <collection>: <n> matched, <nModified> modified")`.

### S5 — dispatch and paging stay coherent; shared result shape grows additively

- `TypedStatementResult` and `StatementResult` gain `message: Option<String>`; every existing
  construction site fills `None` (find keeps "find N"-only tags, insert keeps
  "insert <n>", postgres maps its `CommandComplete`-shaped tags with `None`).
- `query_page_start` keeps working for `find` only: `delete` / `update` statements passed to
  paging return the existing `Protocol` "cursor paging requires a find statement" without
  touching the wire.
- The text surface (`execute_statement`) copies the message through unchanged.

### S6 — live smoke against the `anydb-mongo` container

- Example: `cargo run -p anydb-mongo --example delete_update_smoke -- [target]`.
- Default target `mongodb://localhost:27017/anydb-scrap` — a dedicated throwaway database, so
  the `vuce-landing` fixture and the `anydb_smoke` census are never written.
- Flow: seed three documents through the OWN insert statement (`insert docs with {...}` ×3),
  `update` one via the operator form and assert accepted counts (1 matched / 1 modified),
  `delete` one via the confirmed seam and assert "1 document(s) removed", verify the survivor
  through `find`, `delete` the remaining two, and assert the collection is empty. Every
  acceptance message is printed to stdout; non-zero exit means a failed assertion.
- The confirmed-seam refusal is exercised live too: issuing the delete through the ordinary
  typed path must fail with the seam-naming `Protocol` error while the connection stays
  usable afterwards.

## Tasks

| ID | Spec | Route | Status | Evidence |
| --- | --- | --- | --- | --- |
| T1 | S1 | inline | done | RED: the delete/update test block failed to compile, then failed on shape; GREEN: 26 statement tests pass (delete/update parse + filter-requirement + `set` split incl. `'my set version'`, `"my set"`, `'a''set''b'`) — commit `0aba548` |
| T2 | S2 | inline | done | `the_unconfirmed_delete_refuses_and_the_connection_survives` (pre-wire gate refusal naming the seam, then the confirmed delete runs on the same connection) + integration `the_confirmed_seam_defaults_to_the_ordinary_typed_path` (default delegation) — commit `0aba548` |
| T3 | S3, S4 | inline | done | fake mongod asserts `{delete, deletes:[{q, limit:0}]}` and `{update, updates:[{q,u,upsert:false,multi:true}]}` with the compiled filter bound (`QueryParameter::Integer` -> BSON Int64); `writeErrors` surface; missing `n` / `nModified` are protocol errors naming the command context — commit `0aba548` |
| T4 | S5 | inline | done | `message` rides both shared structs (all foreign construction sites `None`); paging rejects delete/update; text surface copies the message — commit `0aba548` |
| T5 | S6, S8 | inline | done | live on mongo 7.0 (`anydb-mongo` container): gate refusal verbatim, `insert 1` x3, `update docs: 1 matched, 1 modified` verified server-side (`find 1`), `delete docs: 1 document(s) removed` (`find 2`), `delete one` surgical leg (`delete docs: 1 document(s) removed`, `find 1`), final `delete docs: 1 document(s) removed`, `find 0` — throwaway `anydb-scrap` db, exit 0 |
| T6 | all | inline | done | `cargo test --workspace` exit 0 (224 passed, 0 failed across all targets), `cargo clippy --workspace --all-targets -- -D warnings` exit 0, `cargo fmt`, `cargo deny check` (advisories/bans/licenses/sources ok) — on the tree of `0aba548` |
| T7 | S7, S8 | inline | done | 3 new tests (29 in statement.rs, 227 workspace-wide, all gates exit 0), copy `delete one` live evidence into the T5 cell (its smoke leg ran on this increment's tree) |

## Log

- L1 (2026-10-19, requirement start, verbatim): "para el delte debe existir una aceptación
  visible y comprensible" — a deletion must not be fireable silently.
- L2 (2026-10-19, decision; asked with a menu, answer verbatim): "Ambos" — the acceptance is
  BOTH shapes: a pre-execution confirmation seam and an explicit typed, legible write result.
- L3 (2026-10-19, decision): the confirmation gate is scoped to `delete` (the user's words
  name delete); `update` executes from the ordinary path with visible acceptance.
- L4 (2026-10-19, decision): destructive defaults follow SQL shape — `delete` removes every
  match (`limit: 0`; no filter-less delete at all), `update` touches every match
  (`multi: true`), upserts stay off. The `u` payload is mongo verbatim; the ODD spec records
  the wholesale-replacement hazard of plain update documents so it is a documented surface
  rule, not a hidden behavior.
- L5 (2026-10-19, evidence): the acceptance result rides on shared structs
  (`message: Option<String>`) so upper layers can render it platform-wide without parsing
  command tags; the tag + count contract of insert/find is untouched.
- L6 (2026-10-19, implementation, commit `0aba548`): main-side deltas worth recording —
  (a) `QueryParameter::Integer` reaches the compiled delete/update filter as BSON `Int64`
  (the find-side binding contract, rediscovered by RED), (b) the ordinary typed surface's
  delete refusal fires at dispatch (before arity checks — an unconfirmed bad-arity delete
  answers the seam message; arity proof lives in the confirmed seam), (c) the update's
  `set` split point is the quote-aware byte scanner `update_split` with doubling escapes on
  both quote kinds, tolerating `set` end-of-statement (empty document text dies in the parse
  pre-wire), (d) `document::parse_document_literal(text, context)` carries the statement's
  command word into every shared-grammar error. Gates: `cargo test --workspace` 224/0,
  clippy `-D warnings` 0, fmt, `cargo deny check` ok; live smoke
  `cargo run -p anydb-mongo --example delete_update_smoke` exit 0.
- L7 (2026-10-19, delivery): the doc commit is `odd/tasks/mongo-delete-update.md` itself
  (single commit right behind `0aba548`). Push stays a human decision per the adopted
  delivery strategy.
- L8 (2026-10-19, iteration 2 decision; user pick "1" = `delete one`): the single-document
  form is `delete one <collection> with <filter-text>` with the token `one` RESERVED right
  after `delete` — the filter grammar's reserved leading `not` precedent, no backtracking
  parse; a collection named `one` is not addressable in this surface. Only the wire `limit`
  changes (0 stays default, 1 for the modifier); the acceptance contract (tag `delete <n>`,
  message shape) is unchanged, and the copy fills the same `message` field. The all-matching
  form remains byte-identical.
