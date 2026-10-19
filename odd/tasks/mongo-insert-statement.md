# mongo-insert-statement — `insert` statement + VUCE landing seed

Objective: give `anydb-mongo` a write statement (`insert <collection> with <json-document>`) and use
the existing anydb connection to seed the VUCE landing data into docker mongo.
Branch: `feature/mongo-insert-statement` (from `main` @ 14ee025). Delivery strategy: `ask-on-risk`,
resolved by the user at delivery to **stacked work-unit commits on the branch** (no pull requests;
push stays a human decision). Test runner: `cargo test --workspace`
+ gates `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo deny check`.

## Specs

### S1 — statement surface accepts `insert`

`parse_statement` accepts exactly two statement forms: the existing
`find <collection> [with <filter-text>]` and the new
`insert <collection> with <json-document>`.

- The document text after `with` is a strict JSON **object** (RFC 8259): nested objects and arrays,
  double-quoted keys and strings with JSON backslash escapes, numbers, `true`, `false`, `null`.
- A top-level array or scalar is a `Protocol` error before any wire round-trip.
- `insert` takes **no** parameters: passing `?` placeholders or any `QueryParameter` fails with
  `Protocol` `"insert statements take no parameters"` (same shape as
  `"find statements without a 'with' filter take no parameters"`).
- Missing collection, empty document text, malformed JSON and an unknown command word are all
  `ConnectionError::Protocol`, raised client-side. Collection names keep the existing rule:
  may not start with `$`.
- Every pre-existing `find` statement string, filter, error message and behavior is unchanged
  (the JSON document parser is a separate module; `filter` is not modified).

### S2 — `insert` executes the mongo `insert` command

- Wire command: `{ insert: <collection>, documents: [ <document> ], $db: <auth-db> }` through the
  existing single round-trip `command()` path (OP_MSG, `$db` injected there).
- Server reply `{ ok: 1, n: <count> }` maps to `TypedStatementResult` with
  `columns: []`, `rows: []`, `command_tag: Some("insert <n>")`, `affected_rows: Some(n)`.
- A reply carrying `writeErrors` (mongo keeps `ok: 1` for write errors) surfaces as
  `ConnectionError` carrying the server `errmsg`, never as a success.
- An empty `documents` array is never sent (arity is validated client-side).

### S3 — dispatch and paging stay coherent

- `execute_statement_typed` / `execute_statement` dispatch `find` → existing find path,
  `insert` → insert path.
- `query_page_start` keeps working for `find` only: an `insert` statement passed to paging returns
  `ConnectionError::Protocol` (`"cursor paging requires a find statement"`) without touching the wire.
- Existing `find` results (`find <n>` tag, affected rows, filter/parameter binding) are unchanged.

### S4 — seed example loads the VUCE landing data through anydb

- Example: `cargo run -p anydb-mongo --example seed_landing -- [target] [data-dir]`.
- Defaults: target `mongodb://localhost:27017/vuce-landing` (the `anydb-mongo` docker container),
  data dir `drivers/anydb-mongo/examples/data/vuce-landing`.
- It issues one `insert components with <json>` statement per group document (the `components`
  collection is fixed by the consumer's `@Document(value = "components")`), then proves the load
  with `find components` and prints the resulting count plus the `authenticationType` values.
- Idempotency: when `find components` already returns documents the example prints the count, the
  exact `mongosh` drop command needed to re-seed, and exits 0 without inserting.
- A non-zero exit means a failed statement or a failed verification read.

### S5 — `authenticationType` values (verbatim from the user's request)

"añadir un atributo a modalOptions authenticationType el item Title "Mercancías Restringidas" valor
AUTH1_AUTH2, title "Mercancías Restringidas - IPEN" el valor AUTH2 y en la principal el valor
authenticationType debe tener valor AUTH1_AUTH2, en el codigo componente 5 en el modaloption con
title "Gestión de Naves 2.0" el valor authenticationType es igual AUTH2 y de alli todos los demas
tanto en padre como en hijos el authenticationType sera AUTH1"

Acceptance (derived from that text, no other requirement added):

| object | `authenticationType` |
| --- | --- |
| component whose modal option is titled `Mercancías Restringidas` ("la principal", group 1 code 1) | `AUTH1_AUTH2` |
| modal option titled `Mercancías Restringidas` | `AUTH1_AUTH2` |
| modal option titled `Mercancías Restringidas - IPEN` | `AUTH2` |
| modal option titled `Gestión de Naves 2.0` (component `codeComponent` 5) | `AUTH2` |
| every other component (`authenticationType` on the parent) | `AUTH1` |
| every other modal option (`authenticationType` on the child) | `AUTH1` |

Source payload: `https://gateway-apim.vuce.gob.pe/pass-through-https/autenticacion2/landing-componentes/1.0/aplicaciones`
(committed verbatim as `examples/data/vuce-landing/aplicaciones.json`).

### S6 — document shape matches the consumer entities (assumption, flagged)

The consumer (`auth-landing-componentes-api`) reads with `findByIsActiveEquals("1")` on a **String**
`isActive`, so group `isActive` is stored as the string `"1"` (the payload carries the number `1`).
`codeComponent` and `hasModal` are stored as their entity-declared strings (`"1"`, `"true"`,
`"false"`), matching `ComponentEntity`. Everything else is stored verbatim from the payload.

## Tasks

| ID | Spec | Route | Status | Evidence |
| --- | --- | --- | --- | --- |
| T1 | S1 | inline | done | RED: new tests fail to compile + `insert_statements_parse_their_collection` fails; GREEN: 28 `document` tests pass — commit `9d80eb1` |
| T2 | S2 | inline | done | RED: `insert_statement_ships_the_parsed_document` + `insert_write_errors_stay_errors` fail; GREEN: fake mongod asserts `{insert, documents, $db}` and the `E11000` reply surfaces — commit `9d80eb1` |
| T3 | S3 | inline | done | RED: `insert_failures_never_reach_the_wire` + `paging_rejects_insert_statements` fail; GREEN: dispatch + `"cursor paging requires a find statement"` — commit `9d80eb1` |
| T4 | S4, S5, S6 | inline | done | `group-1/2/3.json` from `transform.mjs` (assertions pass); live `seed_landing` run: `insert 1` ×3, `find 3`, census `AUTH1_AUTH2=2 AUTH2=2 AUTH1=19` — commits `136a18e` (data) + `d7f70e3` (example) |
| T5 | all | inline | done | `cargo fmt --check` ok, `clippy --workspace --all-targets -D warnings` ok, `cargo test --workspace` ok (23 targets), `cargo deny check` ok — verified on the state held by `d7f70e3` |

## Log

- L1 (verbatim): "quiero habilitar una coleccion \"vuce-landing\" de datos en mongo de docker
  utilizando la conexion ya anydb la data estraer esta aqui:
  https://gateway-apim.vuce.gob.pe/pass-through-https/autenticacion2/landing-componentes/1.0/aplicaciones,
  añadir un atributo a modalOptions authenticationType el item Title \"Mercancías Restringidas\"
  valor AUTH1_AUTH2, title \"Mercancías Restringidas - IPEN\" el valor AUTH2 y en la principal el
  valor authenticationType debe tener valor AUTH1_AUTH2, en el codigo componente 5 en el modaloption
  con title \"Gestión de Naves 2.0\" el valor authenticationType es igual AUTH2 y de alli todos los
  demas tanto en padre como en hijos el authenticationType sera AUTH1"
- L2 (decision, 2026-10-19): asked how to load the data and where; answer verbatim:
  "Siembra usando anydb (27017)". Consequence recorded: `anydb-mongo` today only speaks `find`
  (`parse_statement` rejects every other command), so the `insert` statement is implemented first
  (accepted scope: "el statement `insert` (grammar + OP_MSG + tests)").
- L3 (evidence): consumer entities already carry `authenticationType`
  (`ModalOptionEntity`, `ModalOptionDto`, `ComponentEntity`) and `ComponentAssembler` maps by name
  (ModelMapper), so no Java change is required; only the data is missing.
- L4 (evidence): `auth-landing-componentes-api/src/main/resources/application.yaml` points at
  `mongodb://localhost:27018/vuce-landingz` (container `landing-api`, empty) while the seed target
  chosen in L2 is `anydb-mongo` on 27017. **Open:** the yaml must be repointed for the API to read
  the seeded data; raised with the user at delivery, not changed unilaterally.
- L5 (evidence): UI semantics confirmed in `contingency-option.ts` — only `AUTH2` and
  `AUTH1_AUTH2` depend on the contingency flag, `AUTH1`/absent take the normal flow, so the S5
  default of `AUTH1` does not alter behavior for the components that had `null`.
- L6 (2026-10-19, T1): `src/document.rs` — dependency-free JSON document-literal parser
  (`parse_document_literal`) producing the shared `bson::Document` shape, 28 tests (nested
  objects/arrays, escapes incl. surrogate pairs, all number shapes, `null`, top-level
  array/scalar rejection, malformed input). Observed RED: 28-target compile failure of the new
  test target; observed GREEN: `test result: ok. 28 passed; 0 failed`.
- L7 (2026-10-19, T2/T3): number shaping moved from `filter::number_bson` to `bson::number_literal`
  (the filter keeps a `number_bson` wrapper that re-adds the `"mongo filter: "` prefix — existing
  `filter`/`bson` tests unchanged and green, so `filter.rs` behavior is preserved). `parse_statement`
  now returns `Statement::{Find, Insert}`; the `unsupported statement:` prefix is factored into
  `statement_protocol`, and the only `find` message that changed is the command-form hint, which
  now also names `insert` (no test asserted its text). `wire.rs::insert` sends
  `{insert, documents: [doc]}` through `command()`, reads `writeErrors` out of the reply before the
  count, and `count_field` rejects a reply without an `n`. Observed RED: 5 tests fail (1 lib parse,
  4 statement); observed GREEN: 84 lib + 35 integration tests pass.
- L8 (2026-10-19, T4): live seed against `anydb-mongo` on 27017 — `insert 1` per group ×3, then
  `find components -> find 3` and census `AUTH1_AUTH2=2 AUTH2=2 AUTH1=19` (= 17 components
  `1/16` + 6 modalOptions `1/2/3`, matching `transform.mjs`'s own assertions). Independent
  mongosh read-back: `isActive` string `"1"`, `codeComponent` string `"1"`, `hasModal` string
  `"true"`, `c.find({isActive:'1'}).count() === 3`, modal `"Mercancías Restringidas" -> AUTH1_AUTH2`,
  `"… - IPEN" -> AUTH2`, `"Gestión de Naves" -> AUTH1`, `"Gestión de Naves 2.0" -> AUTH2`.
  Second run skipped the load and printed the re-seed hint (idempotency, exit 0).
- L9 (2026-10-19, T5): gates green — `cargo fmt --check`, `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo test --workspace` (exit 0, 23 targets), `cargo deny check` (advisories, bans,
  licenses, sources ok). Nothing committed yet: ~1.4k authored lines exceed the ~400-line delivery
  heuristic, so the chain strategy is resolved with the user before the first commit.
- L10 (2026-10-19, delivery): strategy asked and answered verbatim — "Commits apilados en la rama"
  (stacked work-unit commits on the branch, no pull requests, push a human decision). The ~400-line
  heuristic was exceeded by the insert vertical (986 insertions: grammar, dispatch and wire are one
  behavior — splitting them yields commits that do not compile) and by the seed (502 data + 266
  example). Branch commits, oldest first:
  - `1fc6a34` refactor(anydb-mongo): share number literal shaping between filters and documents
  - `9d80eb1` feat(anydb-mongo): add insert statement with a JSON document payload
  - `136a18e` chore(anydb-mongo): add the VUCE landing seed data
  - `d7f70e3` feat(anydb-mongo): add the seed_landing example
  - `06d52b8` docs: add the ODD feature document for the mongo insert statement

  `1fc6a34` was verified in isolation (everything else stashed, then `cargo test -p anydb-mongo`:
  64 lib + 31 integration tests, exit 0); from `9d80eb1` on, `src/` and `tests/` are byte-identical
  to the state the workspace gates ran green on. Working tree clean at `06d52b8`.
- L11 (2026-10-19, open): `main` advanced past the branch cut point (`bd7fa20`) with `36cb935`
  (SPI transaction control) and `bd7fa20` (README + LICENSE). `36cb935` touches
  `drivers/anydb-mongo/src/lib.rs` with a 3-line module-doc addition at the SAME anchor where this
  feature inserted its doc paragraph, so `git merge-tree` reports "changed in both": a rebase would
  hit a trivial doc-comment conflict (main's added lines are a note that ACID transactions are not
  wired for mongo; this feature's are the `insert` statement paragraph — both belong). The branch is
  NOT rebased or merged; the hashes above stand until the user decides.
