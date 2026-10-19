# DBeaver Core Deconstruction — REA Evidence Digest

Status: complete for the connection-lifecycle / driver-abstraction / statement-concurrency scope.
Canonical REA bundle: `dbeaver-rea-analysis.evidence.json` (open/inspect/extract chain, sha256-bound).

## 1. Artifact identity chain (observed)

| Artifact | SHA-256 | Role |
|---|---|---|
| `dbeaver-ce-windows-x86_64.zip` (CE 26.2.2) | `ea6f4c7cc864d15fc5ce64e4142e1c785acf2699b198bf9a3b0e9db93adb909c` | root artifact (REA `open_binary` bound) |
| `org.jkiss.dbeaver.model_2.0.48.202610041844.jar` | REA-managed, in evidence bundle | core model (via `extract_artifact`) |
| `org.jkiss.dbeaver.registry_1.0.182.202610041844.jar` | REA-managed, in evidence bundle | datasource registry |
| `org.jkiss.dbeaver.model.jdbc_1.0.81.202610041844.jar` | REA-managed, in evidence bundle | JDBC execution context |
| `d8out/classes.dex` (JVM→Dalvik conversion) | `AFF2309929FE31C981A39C5CD2B2D230F235F4A0DFC8CCE0E4DF602C0A71D8D0` | JEB-CE compatible input (auxiliary) |

## 2. Engine chain (observed)

- REA 6.7.0 (`rea-agents`), MCP: `open_binary` → `inspect_artifact` (850 nodes / 1054 occurrences / 0 contradictions) → `extract_artifact` (5 core JARs bound).
- JEB CE `5.48.0.202610071539` headless MCP server v1.3.0 (Docker `eclipse-temurin:21`, engine `jeb-ce:activated2`, `--infile=/targets/d8out/classes.dex`, listen `0.0.0.0:8425` inside container, published `127.0.0.1:8425` on host). REA `inspect_jeb_client`/`list_code_items` evidence: `ev_fc4aa002…`, `ev_0c76ddce…`, `ev_451d1f74…`, `ev_640fd6df…`.
- Engine observations: project = `classes.dex`, first code unit = `…jar.apk/Bytecode` (dex type). `list_code_items` returned `Lorg/jkiss/dbeaver/model/exec/DBExecUtils;` + 4 nested types.
- Decompile attempts `decompile_jeb_item` (JAR-derived unit and real d8 DEX): engine refusal `There is no decompiler available`. Vendor product page confirms **JEB CE ships disassemblers + x86/x86-64 native decompilers only; DEX/Dalvik decompilation is a Pro tier feature**. → JEB decompilation branch CLOSED as an out-of-scope product limitation (not an environmental failure).

## 3. Pseudocode sources (fallback, disclosed)

After the JEB-CE limitation, decompilation used two OSS licenses-free engines on the SAME REA-extracted artifacts:

- **CFR 0.152** (MIT): sha256 `F686E8F3DED377D7BC87D216A90E9E9512DF4156E75B06C655A16648AE8765B2` → `C:\Users\educode\.tools\cfr\out` (model), `out-registry` (registry). Failed on `DBExecUtils.tryExecuteRecover` ("Started 3 blocks at once").
- **Vineflower 1.11.1** (Apache-2): → `out-vf` (model), `out-jdbc` (model.jdbc). Recovered the method CFR dropped.
- DBeaver CE itself is open source (Apache-2), so internal analysis use is unrestricted.

## 4. Behavioral evidence (observed pseudocode)

### 4.1 Connection recovery — `DBExecUtils.tryExecuteRecover` (model, Vineflower)
- Per-thread `ThreadLocal<RecoveryState>` stack: `recoveryDepth`, `recoveryFailed`.
- Try count = 1 + `execute.recover.retryCount`, only when `execute.recover.enabled` and no nested recovery already failed.
- Only `ErrorType.TRANSACTION_ABORTED` / `CONNECTION_LOST` trigger recovery (via adapter `DBPErrorAssistant.discoverErrorType`).
- Recovery actions: transaction-aborted → `InvalidateJob.invalidateTransaction(monitor, dataSource, executionContext)`; connection-lost → `InvalidateJob.invalidateDataSource(..., invalidateConnections=true, ping=false …)`.
- Final error propagates as `DBException` / `DBDatabaseException`; `recoveryFailed` sticky, preventing recursive retries.

### 4.2 Statement concurrency — `JDBCExecutionContext$StatementLock` (model.jdbc, Vineflower)
- Default `NoOpLock.INSTANCE`; upgraded to `SingleThreadLock` when `driver.isThreadSafeDriver() == false` (per driver descriptor, i.e. declared by the driver provider).
- `SingleThreadLock` = `ReentrantLock(true)` (fair) + `ConcurrentHashMap<Long, LockInfo>` traces with stack fingerprints; lock/unlock keyed by `(ownerIdentityHash, threadIdentityHash)` composite; detects unlock from wrong thread; `close()` forbids later lock acquisition.

### 4.3 Connect lifecycle — `DataSourceDescriptor.connect/connect0/openDataSource` (registry, CFR)
- Guards: `connecting` flag and `isConnected()` double-check; `detachedProcess` branch.
- `connect0` sequence: resolve secrets (shared-credentials cache, forced subject via `shared.credentials.default.subject`) → `DBPConnectionConfiguration` clone → `BEFORE_CONNECT` event → optional origin credentials provider → password prompt fallback → `patchConnectionProperties` → handler scan (TUNNEL/PROXY) → `exclusiveLock.acquireExclusiveLock()` → proxy initialize → tunnel initialize → `openDataSource` = `provider.openDataSource(monitor, container)` (the `dataSourceProvider` extension point) → `AFTER_CONNECT` event.
- Failure path: `terminateChildProcesses()` then `handleConnectError`.
- Job layer (from earlier evidence): `ConnectJob`, `DisconnectJob`, `InvalidateJob`, `ConnectionTestJob`, `DataSourceJob`, `DataSourceMonitorJob`, `EndIdleTransactionsJob`, `KeepAlivePingJob` under `runtime/jobs`.

### 4.4 Driver model (earlier REA + inspection evidence)
- Extension point `org.jkiss.dbeaver.driverManager` loads driver descriptors (ext.generic declares 97 declarative drivers via `org.jkiss.dbeaver.jdbcDriver` catalog).
- `DriverClassLoader` + Maven runtime resolution (`mavenRepository` extension point) for on-demand driver downloads.
- `DBPDataSourceProvider.openDataSource` is THE factory seam; no pooled-empty prototype was found (correction stands: **no HikariCP in this build**; pooling → `NoHikari … poolSize` configs? not present; connection reuse is runtime-managed per context).

## 5. Inferred architectural invariants (for `anydb`)

1. Connection lifecycle is job-based and uncoupled from the data model: connect/disconnect/invalidate/keepalive are separate jobs queueable against a `DataSourceContainer` (single instance + per-context execution contexts).
2. Recovery is a bounded, thread-sticky retry loop driven by a pluggable error-type classifier — not a global reconnect watchdog. Sticky-failure avoids retry storms.
3. Per-context statement serialization is adaptive: driver-declared thread-safety chooses no-lock vs fair reentrant lock with owner-tracking (deadlock diagnostics via stack traces).
4. Driver abstraction is three-surface: (a) descriptor catalog (declarative, file-based install), (b) factory seam (`openDataSource`) decoupling connection creation from registry, (c) network handlers (tunnel/proxy) as lifecycle stages between auth and `openDataSource`, all under an exclusive per-datasource lock.
5. Connect is a pipeline of optional stages (secrets → auth provider → events → patch props → proxy → tunnel → open), each stage a narrow interface — maps cleanly onto async middleware in Rust.

## 6. Limitations / unexplored branches (declared)

- JEB-CE decompilation branch closed by product scope (vendor page quote recorded above). JEB CE retained value: unit/code-item inventory and cross-refs for the dex dataset.
- CFR→Vineflower fallback means a few dark methods could differ in decompilation fidelity; `tryExecuteRecover` was the only failure observed in the analyzed scope.
- Not explored: `ext.generic` maven resolution internals, `model.rcp`/`model.sql` layers, pooled connection reuse spin detail (`InvalidateJob` invalidate/ping sub-graph beyond signatures), transaction manager widgets.
- Decompilation artifacts live outside the REA bundle; treat them as supplemental evidence with recorded tool hashes above.
