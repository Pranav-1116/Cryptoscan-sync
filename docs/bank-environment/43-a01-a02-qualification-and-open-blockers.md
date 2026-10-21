# 43 — Broader A01/A02 qualification: evidence and open blockers

[Guide index](README.md) · [Implementation and replay contract](42-estate-streams-graphql-and-exports.md) ·
[Engineering backlog](33-international-bank-engineering-and-rollout.md)

**Local engineering/qualification record, 2026-10-21. A01 and A02 are NOT closed.**
This is not a report of a bank deployment. It separates controls demonstrated
here from refused execution profiles, known failing controls and external tests
that were not run. The original ten implementation steps and six-BOM semantics
remain as documented; this increment does not retroactively certify them.

## Subsequent delivery — read before interpreting the blockers

This guide is the **historical** ledger for the preceding increment. Its two
queued-authority strict failures and response-only SSH limitation are superseded
by [Guide 44](44-queued-authority-and-durable-ssh.md): persisted descriptor
reconciliation, pinned/current initiating authority, compare-and-set claims and
durable SSH jobs/results. [Guide 45](45-redis-tls-sentinel-qualification.md) adds
verified TLS/ACL/Sentinel controls, primary-bound replay resets, subscriber
recovery and executed disposable real-server qualification. Historical failing
counts below are retained honestly, not current unresolved implementation claims.
Positive scope grants, distributed budgets, region binding and actual production
HA/security acceptance are still open. A01/A02 are not declared closed.

## 1. What was actually added

### A02 — reviewed history/export boundary

The reviewed unified SSE/WS/polling surfaces now have owner-partitioned journals,
explicit continuation/gap/reset behavior and fresh long-lived authority.
GraphQL job single/list/batch and runtime rows/summaries, scan exports and
findings CSV now have exact-owner predicates. Foreign/missing scan export IDs
are indistinguishable. Foreign evidence cannot enter an owned scan export just
because it references the same scan ID.

Mixed-source audit packs, engagement archives, exit reports, access-review
exports/lists/attestations and aggregate posture SSE are **refused**, not falsely
advertised as bank-partitioned. The guard checks both tenant catalogue presence
and orphaned non-NULL owned rows. The remaining single-platform aggregate is
not a general all-bank export grant.

The separate file-backed live CBOM stream gains authoritative context and fresh
authority, including when tenant middleware is absent. Its version notification
mechanism is not the new unified journal. Embedded event views in live-environment
and telecom stop using a filtered global cache; their other data sources still
need their own inventory/provenance review.

### A01 — broadened admission review, not universal parity

The review identified that SSH had only one generic admission check, not
per-target/port/protocol exclusion preflight. The SSH API now:

- resolves authoritative estate context independently of optional middleware;
- bounds hosts to 256 and timeout to a finite positive maximum of 30 seconds;
- normalizes and validates the entire endpoint batch before any SSH collector;
- checks SSH target, port, protocol, stop, outage and OT restrictions before
  either host-key or optional KEX probing starts;
- explicitly returns `collection.durable=false` and
  `coverage=HOST_KEY_AND_OPTIONAL_KEX_ONLY`.

This is **not durable SSH receipt parity**, host ownership proof or an actual
SSH/device test. Per-host SSH acceptance is not a reservation for a later KEX
phase, and accepted targets do not imply that the platform enforced every bank
approval/window/QPS constraint. Source:
[network API](../../services/api/api/routers/network.py).

The enterprise structured-inventory discovery API could invoke an expanding
engine/plugins after a preliminary scope parse without a qualified bounded
phase/receipt contract. It now refuses **all** calls to
`POST /api/v1/network/inventory/discover` with 409 before importing/constructing
an executor. This includes `plugins=["none"]`: suppressing one plugin does not
prove every engine follow-up was admitted. This is a deliberate availability
restriction, not a successful implementation of enterprise discovery.

Reviewed offline inventory import/analysis and the previously bounded TLS/TCP
profiles remain available. The monitor's existing plugin refusal remains intact.
Direct library/CLI use of the enterprise engine is not made a qualified bank
execution path by this API gate.

## 2. Executable controls versus known gaps

**Historical matrix at `b70072ad`, not the current implementation verdict.**
Guide 44 supersedes the SSH response-only and two queued-authority gaps;
Guide 45 supersedes the absence of verified TLS/Sentinel engineering evidence.
The original reproduced failures and counts below remain unchanged.

| Boundary | Evidence present | Qualification status / restriction |
|---|---|---|
| API TLS aliases/due/discovery | Existing shared preflight, durable job/ledger and bank-negative suites from guides 35–40 | Locally tested bounded profiles; not all live protocols/vendors |
| Worker scheduled TLS | Existing owner batches, observation freshness and durable result tests | Local contract; distributed admission/budget and live deployment still open |
| NETWORK monitor TLS/IPsec/DNSSEC/bounded TCP | Existing fresh phase checks, ownership, rollback and plugin refusal tests | Only documented bounded profiles; no enterprise plugin expansion |
| SSH API | New stop/outage/target/port/protocol/OT negatives; no collector invoked on refusal; middleware-independent context | Improved preflight only; no durable receipt or live SSH qualification |
| Enterprise inventory discovery API | New sentinel test: engine cannot be called | Disabled with 409 until admitted bounded planning, metering and receipts exist |
| Generic queued execution | Existing policy/source-root gates, queue owner propagation and reliability tests | **Known authority gaps reproduced below; not A04-qualified** |
| SSE/event WS | Actual persisted sessions/keys, fresh revocation, prequeue privacy, handoff and overflow recovery tests | Locally qualified retained protocol; not indefinite history or exactly-once |
| GraphQL jobs/runtime | Real SQLite owner/filter/count/summary/batch checks | Reviewed fields only; not a general GraphQL engine/authorization certification |
| Scan/findings exports | Positive owned exports, foreign/missing negatives, count-before-limit and poisoned-evidence checks | Reviewed routes only; not every report/graph exporter in the product |
| Audit/access-review aggregates | Bank/mixed/orphaned estate refusals | Fail-closed restriction; no bank-specific multi-source archive implementation |
| Aggregate posture SSE | Bank/mixed-estate refusal and fresh checks on single-platform stream | Not a bank-partitioned posture export; snapshot/history APIs need separate review |
| Same-tenant country/legal-entity separation | No new geographic ABAC, regional dispatch or declassification migration | **Not qualified**; tenant membership is not residency approval |

A preserved curated platform inventory is not a historical execution grant.
Do not remove ORM guards or relabel legacy NULL records to make an acceptance
case pass. Classify ambiguous historical owners with the bank's data owner first.

## 3. Two known generic queue failures, explicitly not passed

[Broader qualification tests](../../services/api/tests/unit/test_broader_admission_qualification.py)
contain two **strict expected failures**:

1. Persisted job is owned by bank A; the dequeued descriptor presents the same
   job ID but bank B ownership. The generic executor enters the descriptor's
   estate instead of reconciling it with the authoritative persisted job.
2. A job is queued by a valid user, then that initiating user is disabled before
   execution. The generic execution gate does not revalidate that live identity.

Both tests replace the binary collector with a recording sentinel: no file
parsing, device access or network probe occurs. The expectation is refusal;
the current generic executor reaches the sentinel. Therefore these cases are
`xfail`, **not successful isolation tests**. Strictness means an unexpected pass
will force the qualification record/test to be revisited after a genuine repair.

Inspected code:
[queue descriptor](../../services/worker/worker/core/job_consumer.py),
[generic executor](../../services/worker/worker/core/job_executor.py),
[execution policy gate](../../services/worker/worker/core/execution_gate.py).

Owner propagation and an execution-time policy gate are useful but different
from signed/current authority. Keep queue credentials/ACLs tightly controlled;
do not claim that protection against arbitrary Redis producers or mid-queue
principal revocation is implemented here. No queued-authority feature was
silently bypassed or declared complete by these new history changes.

Before qualifying generic queued jobs for a bank, define and implement:

- persisted job/estate/target reconciliation and immutable enqueue authority;
- live principal, role, membership and approval checks at dequeue/retry;
- trusted region/environment/destination, approval expiry and phase limits;
- an explicit legacy queue-envelope migration/refusal policy;
- duplicate/redelivery/idempotency and refusal/receipt behavior under DB failure.

## 4. Standalone Redis evidence actually executed

A disposable **Redis 6.2.14** binary, obtained through the sandbox's test-only
`redislite` package, ran with:

- **no TCP listener** (`--port 0`), a private Unix socket;
- AOF enabled and `appendfsync=always` for the restart experiment;
- isolated test namespaces; tests never run FLUSHDB/FLUSHALL on a supplied server;
- no bank data, production credentials or external Redis service.

The version identifies the experiment; it is **not a recommendation or security
approval to deploy this old Redis version**. The package/binary was not added to
the application's runtime requirements or Git.

Executed real-server tests cover text and byte clients, cross-bus Pub/Sub fanout,
restarting an API reader against the same retained journal, paginated exact-estate
reads after foreign publication, exact trimming, missing middle records and
wrong-type refusal before estate writes. The initial six integration cases
passed, and the combined real-server + memory/emulator journal run passed 37
cases at that stage. A subsequent journal-only run passed **44 cases**: 36
memory/emulator cases and **eight real-server cases**, including byte/text concurrent writers
across two estates. Every accepted input must appear exactly once in contiguous
estate sequence; bounded contention refusals are explicitly permitted and checked,
not counted as accepted writes or disguised as general fairness guarantees.
Deterministic emulator interleavings additionally pin a concurrent commit between
metadata and stream reads for both append and page operations.

A separate manual experiment seeded a frozen cursor at estate sequence 1 of 3,
then:

1. gracefully terminated Redis and observed explicit connection refusal rather
   than a fallback to an available fake local cache;
2. restarted the same Redis process configuration from the AOF directory;
3. verified the same epoch/watermark and remaining estate sequences 2–3 with no
   retention gap.

That proves this narrow **graceful AOF process-restart/outage** scenario. It does
not prove power-loss safety, SIGKILL timing, Sentinel failover, Redis Cluster,
replication lag, partition recovery, multi-region replication, backup restore,
capacity, tenant fairness or deployment persistence configuration. The server
also warned that host memory-overcommit settings were not configured; they were
not changed or treated as qualified by this test.

### Reproduce the opt-in command/fanout cases

Use a disposable supported Redis instance/socket, not a bank production service.
Configure/start it through the approved process supervisor, then run:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
export ESTATE_REPLAY_REDIS_SOCKET=/path/to/disposable/redis.sock
python -m pytest -q services/api/tests/integration/test_estate_replay_redis.py
```

Without the socket environment variable these integration cases skip; a skipped
case is not real Redis evidence. The eight cases do not themselves restart a server;
the manual AOF experiment above is a separate, accurately scoped observation.

## 5. Final local validation ledger

Executed local results (counts are not additive: suites overlap):

| Check | Actual result / scope |
|---|---|
| Replay + SSE + sockets + GraphQL/exports + broader admission + initial six real-Redis cases | **198 passed, 2 strict xfailed**, 4 warnings; includes deterministic WATCH interleaving fixes |
| Final journal, all eight real-Redis cases and legacy bus/federation contracts | **63 passed**, 3 warnings; includes concurrent accepted-write completeness and two missing-publisher refusals |
| Final SSE/CBOM authority and fault controls + legacy stream API | **43 passed**, 4 warnings; includes three final CBOM initial/read-failure and mid-read revocation cases |
| Broad API/worker/database/eventstream/network-scanner coverage | **3,747 unique passed, 5 skipped, 2 strict xfailed across interrupted broad + fresh remainder runs**, NOT one clean full run; see interruption below |
| Frontend full regression | **43 files / 384 tests passed**, 270.62 s; existing React `act(...)` and performance warnings |
| Frontend typecheck and production build | **Passed** on the final frontend source |
| Changed Python F/E9, selected journal/stream/contract formatter and whitespace checks | **Passed** |
| Markdown relative references and Python example syntax | **247 relative references across 8 changed guides/index files checked; no broken targets** |

The four-worker broad process reported **3,698 passed, 2 skipped and 2 xfailed**
before all four workers terminated at 98%. xdist marked four in-flight cases
failed and then exited 3 with an internal scheduler `KeyError`. The termination
cause was not established; this is **not a clean full-suite pass**.

A fresh collection on the final source contained **3,754 cases**. Subtracting
only the broad process's completed pass/skip/xfail node IDs left **52 cases**,
including all four crash-marked cases and five cases added after startup.
Those exact cases were rerun serially: **49 passed, 3 skipped**, 44 warnings.
A node-ID set-union check confirmed every collected case has a completed result
across the two runs, with no missing cases. The five skips require disposable
PostgreSQL qualification infrastructure; they do not count as passes.

The final 43-case SSE/CBOM rerun additionally covers the post-storage-read
authority/fault controls. The final 63-case journal/bus run covers the missing-
publisher fail-closed guard, all eight real-Redis cases and legacy federation
contracts. The focused 198-pass run collected only the initial six real-Redis
cases. These overlapping counts must not be added together as independent tests.

The underlying test commands are:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest -q services/api/tests/unit/test_estate_replay.py \
  services/api/tests/unit/test_sse_estate_contract.py \
  services/api/tests/unit/test_socket_history_contract.py \
  services/api/tests/unit/test_cross_surface_estate_contract.py \
  services/api/tests/unit/test_broader_admission_qualification.py \
  services/api/tests/integration/test_estate_replay_redis.py --timeout=40
# The real-Redis cases need ESTATE_REPLAY_REDIS_SOCKET as above.
python -m pytest -q services/api/tests/unit/test_estate_replay.py \
  services/api/tests/integration/test_estate_replay_redis.py \
  services/api/tests/unit/test_event_bus.py \
  services/api/tests/unit/test_realtime_shared_state.py \
  services/api/tests/unit/test_realtime_durable_events.py --timeout=40
python -m pytest -q services/api/tests/unit/test_sse_estate_contract.py \
  services/api/tests/unit/test_stream_api.py --timeout=40
python -m pytest -n 4 --dist loadfile -v services/api/tests/unit \
  services/worker/tests/unit services/database/tests \
  services/eventstream/tests services/network_scanner/tests --timeout=40
```

```bash
cd frontend
npm run typecheck
npm test -- --maxWorkers=1
npm run build
```

The source checks use F/E9 lint on changed Python, formatter checks on the new
journal/contract code and changed stream/socket foundation, whitespace checks,
and bank-guide link/example validation. No workflow or main-branch changes are
part of this delivery. Publication uses `[skip ci]`, as requested; local tests
are not described as GitHub CI executions. Deprecation warnings (Pydantic,
Starlette/httpx, Alembic and legacy TLS fixture versions), existing model-field
shadow warnings and frontend React `act(...)` warnings are not security passes.

An earlier broad run failed five cases: a genuine false-corruption WATCH read
race, obsolete fake-Redis/fallback assumptions, the lost replay-gap counter
increment, and an end-to-end fixture giving a read-only role to a cascade writer.
The race was fixed by confirming a stable watched version before corruption
refusal; the counter was restored; tests now use actual emulator commands and
configured-journal refusal; the membership fixture uses `security_analyst`, not
platform admin. Failure was not hidden by allowing arbitrary replay exceptions
or by weakening estate/role authorization. The concurrent test permits only the
explicit bounded-contention refusal and reconciles every accepted payload and
sequence. Incomplete/stopped earlier test processes are not completed evidence.

## 6. Bank release gates still open

**Historical release-gate list for this increment.** Durable SSH and the two
queue controls listed below are implemented by Guide 44. Verified transport,
command readiness and disposable Sentinel evidence are added by Guide 45.
Positive/regional grants, distributed budgets, remaining profiles, product-wide
segregation and deployed production qualification remain open; these later
increments are not a declaration that A01/A02 are closed.

1. **A01 admission and receipts:** implement durable SSH collection and all
   remaining execution profiles, positive scoped grants/expiry, actual QPS and
   connection budgets, bounded in-flight stop and atomic distributed reservation.
   A target validator or an exclusion list is not positive bank authorization.
2. **A02 data architecture:** classify historical NULL ownership and curated
   sharing, decide legal-entity/region ABAC and export residency, inspect remaining
   report/graph/cache/security aggregate surfaces, and define approved segregation
   or migration. This delivery is not a product-wide access-control certification.
3. **A04 execution:** close the two known queued-authority failures and qualify
   retry, revocation, forged envelopes, cross-owner persistence and region binding.
4. **Redis/replay operations:** supported/patched deployment version, TLS/ACLs,
   persistence/restore, eviction policy, per-estate capacity and retention sizing,
   contention/load tests, Pub/Sub loss, HA/failover and cross-region failure tests.
   Redis Cluster needs a separately designed cross-slot strategy.
5. **Storage/runtime evidence:** real disposable PostgreSQL parity where used,
   Neo4j where selected, approved hostile-input runtime and representative vendor/
   device/country canaries. SQLite, fakeredis and a local standalone Redis are not
   substitutes for those results.
6. **Audit acceptance:** bank-specific mixed-source packs, reviewed access-review
   tenancy, export redaction, retained receipt reconciliation and signed-off restore.
   A refusal is a safe restriction, not delivery of the requested bank archive.

For a production pilot, constrain enabled routes/credentials to the documented
qualified profile and obtain explicit acceptance of every remaining restriction.
Do not enable an unqualified path because a UI lists its name or a fixture can
stub its collector.

## 7. Six-BOM/provenance invariant

- **NBOM:** bounded network observations; port discovery alone is not TLS/crypto.
- **CBOM:** extracted/observed cryptographic facts, not arbitrary generic findings.
- **SBOM:** package/artifact evidence, not proof a release was deployed.
- **TechBOM:** explicitly supported technology/system relationships, not inferred
  operational causation from an event's delivery order.
- **HBOM:** hardware/firmware evidence with its own collector/source limitations.
- **VBOM:** supplier evidence and declarations, not automatic signature trust or
  a claim every vendor connector exists.

A journal replay only redelivers stored facts. It does not refresh their observed
clock, upgrade an operator declaration to a measurement, certify a supplier,
create missing dependency links, or prove that an estate was completely scanned.
