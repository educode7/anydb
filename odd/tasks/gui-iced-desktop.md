# gui-iced-desktop — first visual test surface (iced desktop GUI)

Objective: ship the first visual surface to test the anydb platform live — a desktop app
(iced) that connects from a URL, runs SQL from an editor, and renders the typed result in a
grid, all through the public `App` pipeline (recovery included). User scope: "Interfaz
gráfica (tipo DBeaver)", stack "Prefiero iced".
Branch: `feature/gui-iced` (from `main` @ 64fb876), worktree
`C:\Users\educode\Documents\anydb-worktrees\iced-gui`. Delivery strategy: stacked
work-unit commits on the branch (same as mongo-insert-statement; no pull requests; push
stays a human decision). The ~400-line planning heuristic is exceeded for the same reason
the insert vertical recorded: the bridge, the events and the screen are one behavior —
splitting them yields commits that do not compile. Test runner: `cargo test --workspace`
+ gates `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo deny check`.

## Specs

### S1 — workspace member `apps/anydb-desktop`

- New binary crate `apps/anydb-desktop` (the workspace's first `bin` target), added to the
  root `Cargo.toml` `members` list. `publish = false`.
- UI framework is `iced` (user's exact choice: "Prefiero iced").
- The crate depends on `anydb` (the composition root) and `tokio` (workspace feature set).
  No existing crate changes behavior; only the root `members` list and `Cargo.lock` move.
- Workspace discipline holds: `#![forbid(unsafe_code)]`, `cargo fmt --check`,
  `clippy -D warnings`, `cargo deny check` all pass with the new member.

### S2 — UI/async bridge: worker thread + channels, no awaits on the UI thread

- iced owns the main thread (winit requirement). The platform `App` runs inside ONE
  dedicated tokio `Runtime` created on a background worker thread.
- UI -> worker: a `std::sync::mpsc` command channel with commands
  `Connect { url }`, `Disconnect`, `Status`, `Execute { sql }`, `Shutdown`.
- Worker -> UI: a `std::sync::mpsc` event channel with
  `Connected`, `Disconnected`, `StatusChanged(text)`, `ExecutionFailed(text)`,
  `ResultReady(TypedStatementResult)`.
- The UI drains the event receiver every frame (no thread is ever blocked on a channel);
  the worker never blocks the UI thread. Sending on a closed receiver is a no-op (window
  closing during an in-flight command must not panic).
- `Connect { url }`: the worker parses the URL, builds the driver + properties (reusing the
  existing driver URL parsers and the driver's `Driver` impl), registers ONE container on
  the `App` (a second connect replaces it via a new container id), then calls
  `App::connect`. One container id constant, defined by the crate.
- `Execute { sql }` runs `App::execute_statement_typed(id, sql, &[])` — empty params in V1;
  the recovery pipeline is therefore exercised unchanged (spec: the UI never calls a
  driver directly).
- Shutdown: `App::shutdown().await` then the runtime drops; the thread joins on window
  close.

### S3 — connection events reach the UI

- A concrete `ConnectionEvents` sink (the platform port; `NoOpEvents` today) forwards
  `ConnectionEventKind` changes into the worker -> UI event channel as `StatusChanged`.
- The sink is passed to `App::new` at worker startup; no platform change is needed.

### S4 — V1 screen: connect, status, execute, see results

- Top bar: URL text field + Connect button + Disconnect button + status text (from
  `StatusChanged` / command outcomes).
- Editor: multiline SQL text area + Execute button.
- Results region renders `TypedStatementResult`:
  - column headers from `columns`;
  - one line per row from `rows` (`TypedValue` rendered with its `Display`);
  - when `command_tag` / `affected_rows` / `message` are present, a summary line shows
    them (e.g. mongo delete acceptance "delete <collection>: <n> document(s) removed").
- Errors from any command render in a visible error line (`ExecutionFailed`), never a
  panic and never silently dropped.
- V1 does NOT include (recorded, not requested): catalog/schema tree, result paging,
  statement cancel, parameter binding UI, secrets store wiring (URL carries credentials).

### S5 — verification

- Deterministic tests where a runnable RED exists: the worker command loop is tested with
  a fake `Driver` (same pattern as `tests/integration.rs`) driving connect/execute to
  `ResultReady` / `ExecutionFailed` assertions, without any window.
- The iced `view`/layout is passive composition: checked by compile + gates, not a
  semantic test (no GUI harness in scope).
- Gates run at every work unit: fmt, clippy `-D warnings`, `cargo test --workspace`,
  `cargo deny check`.

## Tasks

| ID | Specs | Route | Status | Commit |
| --- | --- | --- | --- | --- |
| T0 | — | inline | done | worktree `iced-gui` + branch `feature/gui-iced` (no commit) |
| T1 | S1 | inline | done | scaffold: member + iced 0.14 + main.rs |
| T2 | S2, S5 | inline | pending | — |
| T3 | S3 | inline | pending | — |
| T4 | S4 | inline | pending | — |
| T5 | S5 | inline | pending | — |

## Log

- L1 (user, verbatim): "que esta faltando para poder probar con una vista?" -> clarification:
  "Interfaz gráfica (tipo DBeaver)"; stack decision: "Prefiero iced";
  worktree request: "crear un wordtree".
- L2: evidence map delivered (no bin/UI crate exists; no catalog metadata; paging not
  surfaced; no cancel API). V1 scope cut to URL form + editor + grid per S4.
