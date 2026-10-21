# 37 — NETWORK monitor owner, transaction and freshness isolation

[Guide index](README.md) · [Scheduled TLS worker](36-worker-scheduled-tls-admission.md) ·
[Enterprise backlog](33-international-bank-engineering-and-rollout.md)

## Subsequent delivery

[Guide 38](38-monitor-network-phase-admission.md) now supplies admission and
linked jobs for bounded monitor TLS/IPsec/explicit-resolver DNSSEC. Automatic
scope/plugins are refused before execution. This guide records the preceding
lifecycle delivery and its then-open boundary; guide 38 supersedes those profile
execution/admission statements, without changing its historical test evidence.
[Guide 39](39-bounded-tcp-monitor-discovery.md) subsequently qualifies an explicit
bounded IPv4 TCP discovery profile only; expanding scope/plugins remain blocked.

## Status: supporting A01 delivery, not protocol admission parity

**Implemented locally, 2026-10-19. A01 is still partial.** This delivery covers
the lifecycle of NETWORK rows in `monitor_targets`, including sequential and
thread-pool execution and the synchronous monitor `scan-now` path. It is separate
from guide 36's `network_scan_targets` scheduled TLS rotation.

The implementation now gives these passes trusted owner context, isolated
acceptance/failure transactions, target-qualified live projections and honest
freshness. It does **not** migrate `network_runner` to the shared phase-specific
admission and ScanJob/NetworkScanRun collection contract.

> **Security boundary still open:** NETWORK monitor TLS, scope, IPsec and DNSSEC
> phases do not yet have admission/receipt parity with the guide 35 API routes
> or guide 36 scheduled TLS sweep. Central stop/window/budget enforcement,
> target/port/protocol admission and linked pre-execution jobs for these profiles
> remain required work. In particular, the existing TLS-only SSRF filter is not
> qualification of IPsec destinations, DNS resolvers or discovery plugins.
> Do not enable unqualified profiles in a bank that requires those controls.

No migration, workflow change or historical evidence rewrite is included.
There is no claim of live bank/device, PostgreSQL/Neo4j or vendor qualification.

## 1. Why this lifecycle work comes before the next admission migration

The prior engine ran a NETWORK adapter without entering its persisted owner's
context. Explicitly tenant-tagged monitor events did not make every certificate,
usage, live-state or replay-event write tenant-scoped. A shared daemon session
could also contain pending changes from a previous target when another failed.

Other reproduced defects were:

- projections and metering ran before a blocked result was recognized;
- SQL flush errors could leave a failed transaction in use while the engine
  tried to write its failure diagnostic;
- certificate storage and IPsec/DNSSEC exceptions were silently swallowed;
- blocked and incomplete results could advance `last_scan_at`;
- a projection replaced **all** current NETWORK state for an estate/scanner,
  including observations owned by another monitor target;
- thread workers and the forever loop committed in `finally`, even after an
  unhandled operation had aborted;
- alert callbacks ran before their target state had been accepted in SQL.

The initial lifecycle regression draft produced **19 failures**. A subsequent
runner-focused expansion produced **16 failures with the 19 lifecycle cases
passing** before its fixes. These were controlled local reproductions, not
reports of a bank outage.

## 2. Trusted ownership and transaction boundaries

[MonitorEngine](../../services/worker/worker/monitor/engine.py) now dispatches
NETWORK targets through a dedicated lifecycle wrapper:

1. A tenant-scoped caller may execute only its exact owner, never a shared NULL
   platform row or a foreign bank's target. A refused internal lookup returns
   `GONE` without executing or creating a target event. API authorization still
   performs its own existing 404/role checks.
2. Commit preceding monitor/watch work before changing the session's owner
   context. The NETWORK wrapper owns its commit/rollback boundaries; callers
   must not expect a later rollback to undo an already accepted network pass.
3. Reload the persisted row, then enter `tenant_scope(row.tenant_id)` for the
   adapter, projections, metering, status and events. Configured `tenant_id`
   fields are not execution authority.
4. Recheck enabled state and the actual tenant registry. Paused targets and
   missing/suspended owners are BLOCKED without running the adapter. An unscoped
   leader intentionally operates the fleet, including platform-owned rows.
5. Accept adapter SQL writes, common live projections, metering and target/event
   updates together. On failure, roll back before writing a failure diagnostic
   in a clean transaction. An actual persistent DB outage can still prevent
   that diagnostic; the code must not claim it was saved.

The existing failure backoff remains: one exception degrades, consecutive
exceptions fail, with capped exponential retry. A returned incomplete observation
is DEGRADED and scheduled at the normal interval; it is not counted as an
exception failure or a confirmed outage. This is still the legacy per-pass meter,
not the shared per-host quota preflight/reservation contract.

Other domain adapters retain their existing owner and accounting behavior; this
is not general repository/cloud/plugin parity. In particular, this patch does
not reinterpret the legacy repository runner's config override as trusted bank
ownership for all purposes.

## 3. Sequential, threaded and forever-loop execution

A thread does not automatically inherit the request's ContextVar tenant scope.
The pool explicitly carries the caller scope into row lookup and execution;
the NETWORK wrapper then uses the persisted owner for the pass. The parent
commits watch/config changes before workers open their own sessions—flushing
alone would not make those changes visible across connections.

Workers now commit only after their operation returns successfully. An
unhandled worker exception rolls back and closes its session, rather than
accepting staged writes in `finally`.

[MonitorLoop](../../services/worker/worker/monitor/loop.py) similarly commits
only a successful tick. A tick/commit exception triggers rollback, then close,
and the forever loop continues. Previously committed NETWORK passes remain
accepted if later work fails; this is not an all-fleet transaction or a fairness
guarantee. Persistent first-target/DB faults can still delay later work.

## 4. What counts as a fresh observation

A NETWORK result must explicitly return the boolean
`observation_complete=True` to refresh `last_scan_at` and permit replacement of
its current projection. Missing, string or numeric substitutes are not proof.
Custom internal runners/test adapters must adopt that contract too.

The official [network_runner](../../services/worker/worker/monitor/runners.py)
now reports completeness conservatively:

| Profile/outcome | Whole-target freshness |
|---|---|
| TLS `OK` or `PARTIAL`, with `probed == ok == configured endpoint count` | Eligible, provided no other phase/filter/expiry failure made the pass incomplete |
| TLS error, missing/unknown telemetry or incomplete counts | Incomplete; retain prior freshness |
| IPsec telemetry observes every configured target and all respond | Eligible as an observation, not admission or device-safety qualification |
| IPsec exception or incomplete responses | Explicit issue; incomplete |
| Scope discovery | Coverage not established; do not infer that all expansion/plugin/capped work completed |
| DNSSEC | Coverage not established; current checker can suppress individual DNSKEY/DS/AXFR query errors, so SIGNED/UNSIGNED alone is insufficient |
| Blocked/paused/missing owner | No adapter execution, projection, metering or freshness refresh |

Successful scope/DNSSEC probes are **not removed or disabled** by this change.
Their available positive observations/issues are retained, but full-target
freshness is withheld and coverage uncertainty is visible. Fixing the underlying
phase completion and authorization contracts remains next work, not a claim
that a DNS zone is broken or a discovered bank service is down.

Incomplete results carry `observation_complete=false` in the rolling summary
and the `OBSERVATION_INCOMPLETE` issue. Scope/DNSSEC add explicit coverage-not-
established issues. Extra-phase exceptions now surface named errors instead of
silently returning clean. Expiry-check errors also withhold completeness.
Certificate/usage storage errors propagate to the engine and roll back acceptance.

The official scanner now explicitly uses **8 workers by default**, allows 1–32,
and requires a finite, positive timeout of at most 30 seconds. These settings
bound configured TLS concurrency, not the full discovery engine's connection
behavior, shared QPS, distributed budgets or bounded in-flight stop.

## 5. Target-qualified current projections and retained evidence

[realtime_projection.py](../../services/worker/worker/monitor/realtime_projection.py)
now namespaces NETWORK current-state identities by estate, scanner **and target
ID**, with a SHA-256 digest of the component kind/name/version. Long component
names do not become colliding 200-character truncated IDs in the new namespace.

A complete replacement deletes only that target's new namespace, with escaped
prefix matching and an explicit owner predicate. Another monitor target in the
same bank is not evidence that this target's previous state disappeared.

An incomplete pass may add/update its available positive observations and append
journal events, but does not delete absent current state. A failed replacement
rolls back its deletions and staged events. This does not certify every returned
adapter field, establish complete BOM discovery, or fix the separate phase-result
merging/receipt contract.

**Compatibility:** existing legacy scanner-wide current-state IDs are retained,
not automatically reassigned or deleted. They can coexist with the new target-
qualified rows, including duplicate-looking old observations. Consumers must
use target provenance and `last_seen`; do not count old/new IDs as newly proven
physical assets. A safe explicit legacy-state retirement/migration remains open.
Immutable historical events are not re-keyed or rewritten. The globally shared
certificate/target identity and platform-NULL isolation issues remain A02 work.

The available observations remain network/crypto evidence, not invented SBOM,
TechBOM, HBOM or VBOM coverage. This does not alter the six-BOM evidence rules.

## 6. Notifications after acceptance

NETWORK stream publication and new-issue callbacks now occur after the pass's
SQL acceptance, under the accepted owner's context. A callback opening another
SQL connection can see the accepted target state. A completion-commit failure
does not dispatch its rolled-back alerts.

Notification sinks remain best-effort. There is no transactional outbox,
exactly-once guarantee or automatic replay of a notification lost after commit.
The existing alert-once comparison remains, including the newly explicit coverage
issue; incomplete coverage is operational uncertainty, not a confirmed outage.

## 7. Practical example

Two payment-network monitors in Bank A observe the same AES algorithm on two
different endpoints. Each now has its own target-qualified current state and
immutable observation references. A complete refresh of the first cannot delete
the second's current evidence.

On the next pass, the first target returns incomplete TLS telemetry. Its existing
current evidence and previous `last_scan_at` are retained; its summary becomes
DEGRADED with incomplete coverage. If instead a storage flush fails after staging
new data, the engine rolls that pass back and records SCAN_FAILED with backoff.
Bank B's monitor continues in its own owner context; neither a forged config
owner nor a thread's missing inherited context grants Bank B Bank A's writes.

This example is covered with local controlled executors, not a live bank scan.

## 8. Validation and remaining work

[Lifecycle/runner regression tests](../../services/worker/tests/unit/test_monitor_network_lifecycle.py)
use real file-backed SQLite sessions, actual ORM tenant guards and controlled
scanner calls. They exercise owner scoping in serial/threads, foreign reads and
writes, missing/suspended/paused owners, actual SQL flush failure, commit faults,
rollback of preexisting state replacements, blocked/incomplete freshness, callback
visibility, malformed completion flags, profile bounds, legacy retention and
aborted loop/pool writes.

Existing controlled successful runner fixtures now declare completion explicitly.
The alert-once test for unreachable TLS now expects the coverage issue as well,
without re-alerting on steady state. The local IPsec/DNS protocol fixtures still
run, and do not qualify their destination/admission policies.

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest -q \
  services/worker/tests/unit \
  services/network_scanner/tests \
  services/database/tests \
  services/api/tests/unit/test_network_collection_contract.py \
  services/api/tests/unit/test_scan_admission.py \
  services/api/tests/unit/test_specialized_scan_run_records.py \
  services/api/tests/unit/test_monitor_api.py
```

Final local scoped regression: **1,783 passed, 5 skipped, 7 deselected,
139 warnings**, in 275.91 seconds on Python 3.11.2, including **48 new lifecycle/
runner cases**. The post-format focused monitor/API run passed **93 tests**.
Changed-Python F/E9 lint, new-test-file formatting, whitespace and bank-guide
local-link/JSON/shell syntax checks passed. Existing warning classes remain. Skipped/deselected cases are not executions. Controlled SQLite/local
protocol evidence is not PostgreSQL, Neo4j, vendor/runtime or bank qualification.
No production deployment, frontend build, migration or workflow change is claimed.

**Next:** migrate each monitor network profile to checked destination/phase
admission, whole-batch quota and committed pre-execution jobs with linked accepted
probe ledgers. Resolve discovery expansion and DNS resolver/zone-query semantics,
then test stops, exclusions, quotas, storage/reaper failures and zero-packet
refusals across the actual execution paths. Do not call A01 complete from the
lifecycle fixes, or merely wrap TLS and imply other protocol parity.
