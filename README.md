# anydb

Async Rust connection platform for database drivers — a library modeled
from an evidence-backed deconstruction of the DBeaver core (its data
source lifecycle, recovery pipeline and driver SPI, translated to a
horizontally-layered Rust workspace).

Status: work in progress. Two wire-level drivers ship; the platform
contract (SPI, recovery, transactions) grows with each vertical.

## Workspace layout

| Crate | Role |
| --- | --- |
| `anydb` | Composition root: wires infrastructure into the `connections` system and exposes the public surface via `prelude` (`#![forbid(unsafe_code)]` workspace-wide). |
| `anydb-shared` | Driver SPI and contracts: factory seam (`Driver` / `DataSource`), typed statement surface and parameter set, error classification, network ports, transaction control. |
| `anydb-connections` (`systems/connections`) | Supervised connection and execution system: container lifecycle, keepalive pings, invalidation scopes, statement execution through the recovery pipeline. |
| `anydb-postgres` | PostgreSQL driver over wire protocol v3. |
| `anydb-mongo` | MongoDB driver over the OP_MSG protocol. |

## Drivers

### `anydb-postgres`

- Wire protocol v3 from the first byte: startup handshake, SASL
  SCRAM-SHA-256 (with the `md5` path for older servers), `rustls` TLS
  driven by an explicit `ssl_mode`.
- Extended query protocol: named prepared statements, binary-format
  parameters (including exact-decimal `numeric` in the external
  base-10000 form), a SQL-keyed statement cache, and portal paging over
  multiple round-trips.
- Typed decoding through a catalog of binary/text extractors
  (`int2`..`float8`, `text`, `bytea`, `numeric` with `NaN` /
  infinities and display-scale-preserving rendering), plus
  SQLSTATE-driven error classification.
- Live-server evidence under `examples/`: `numeric_smoke` (decode),
  `numeric_bind_smoke` (binary bind round-trips), `paging_smoke`
  (portal paging semantics), `transactions_smoke` (real
  begin/commit/rollback atomicity).

### `anydb-mongo`

- OP_MSG wire protocol with SCRAM-SHA-1/256 negotiation and `rustls`
  TLS; `$db` rides the single-round-trip command path.
- Statement surface: typed `find` with a client-side filter language
  (`$and` / `$or` / `$not` / `$nor`, parity-folded unary `not`),
  validated against a running mongod in the smoke probes; BSON values
  map to the shared `TypedValue` set, including `Decimal128` and UTC
  datetimes.
- Cursor-id paging stays driver-level (like postgres portal paging):
  multi-round-trip reads do not fit the one-shot recovery pipeline.

### Shared parameter SPI

`QueryParameter`: `Null`, `Boolean`, `Integer`, `Float`, `Text`,
`Binary`, `BigDecimal` — typed on the wire for every driver (postgres
declares binary OIDs and builds the wire form; mongo interpolates
`Decimal128` literals client-side), with named bind-time errors where a
driver cannot carry a type. Transaction control
(`begin` / `commit` / `rollback`) belongs to the `DataSource` contract
and degrades gracefully per driver.

## Building and testing

```text
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

Tests run against fake wire backends; the `examples/` probes need a
real server (any local postgres/mongo works — see each example header
for the target it expects).

## License

Apache-2.0 — the full text ships as the `LICENSE` file.
