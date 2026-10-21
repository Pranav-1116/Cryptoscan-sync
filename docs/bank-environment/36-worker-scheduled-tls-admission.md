# 36 — A01 second delivery: leader-worker scheduled TLS collections

[Guide index](README.md) · [First API delivery](35-network-admission-and-durable-collection.md) ·
[Enterprise backlog](33-international-bank-engineering-and-rollout.md)

## Status and exact boundary

**Implemented locally, 2026-10-19. A01 remains partial.** This delivery changes
[network_sweep.py](../../services/worker/worker/monitor/network_sweep.py), the
leader-worker rotation of persisted `network_scan_targets`. These are the rows
registered by network target/onboarding/discovery flows, not the separate
`monitor_targets` NETWORK runner configuration.

The sweep now reuses the API's
[network collection helpers](../../services/api/api/security/network_collection.py).
This deliberately avoids a second, weaker worker-specific policy implementation.
The supported worker image ships the API/shared service packages and root
requirements; this is not a newly independent worker-only distribution.
No schema migration, workflow or existing historical-record rewrite is needed.

**Not delivered by this original increment:** parity for `network_runner`,
IPsec/DNSSEC, SSH/plugins or every adapter. Subsequent guides 37–39 add bounded
monitor ownership/phase/TCP controls; [Guide 44](44-queued-authority-and-durable-ssh.md)
adds durable SSH receipts and queued authority. Expanding inventory plugins and
other unqualified profiles remain refused; these local increments are not bank
or all-protocol certification. The original test evidence below is historical.

## 1. Reproduced defects and regression approach

Before the change, a due TLS target went straight to the scanner. No central
admission, quota preflight or pre-execution ScanJob protected it. A returned error
result still advanced every selected schedule, and persistence errors had no
linked durable attempt. Grouping also depended on a global endpoint lookup rather
than using the persisted owner and row identity together.

The first new regression draft produced **23 failures** against that behavior.
The final scheduled contract suite was expanded to **33 cases**, retaining real
SQL transactions and controlling only policy-data seams and external executors.
An independent SQLite connection verifies that RUNNING is committed before the
fake executor is called. This is not proof of live bank network/device safety.

## 2. Selection, ownership and bounded preflight

1. Select enabled, due persisted rows using the scheduler's UTC clock rules.
2. When invoked under a tenant context, keep only that exact owner. Shared NULL
   platform inventory is not executable authority for a tenant.
3. An unscoped leader deliberately operates the fleet, grouping by persisted
   owner. Tenant IDs are not accepted from a request/config dictionary.
4. Split each owner's work into batches of at most **256 rows**.
5. Before each batch, reload the tenant registry and selected rows. Missing or
   suspended owners, disabled/re-scheduled rows and changed selection are refused
   before any executor is constructed. Previously cached ORM state is not enough.
6. Normalize/validate endpoints, including existing SSRF checks, then centrally
   admit the entire phase with endpoint/port/transport/service exclusions.
7. Check and meter the entire deduplicated batch using the existing per-host
   `scan_run` allowance. Insufficient allowance refuses the whole phase.

Production explicitly constructs `NetworkTlsScanner(live=True, timeout=5.0,
workers=8)`. This bounds configured TLS worker count; it does **not** establish a
shared regional connection budget, packet/QPS envelope or per-device safety
profile. Admission is checked anew between batches, not continuously in flight.

The existing admission rules apply, including stop, unavailable control plane,
OT-derived active-probe restrictions, queue policy and existing maintenance-mode
semantics. This patch does not invent expiry, legal-entity grants, region rules,
DNS pinning or stricter global IT maintenance windows.

## 3. Durable execution and failure semantics

For each admitted batch:

- Meter the admitted per-host attempt and commit a tenant-owned **RUNNING
  NETWORK_SCAN job before constructing the scanner**. The actor is
  `monitor-daemon`; metadata retains the scheduled kind and effective profile.
- Persist the returned result to a **NetworkScanRun** with the same versioned
  `cryptoscan.network-collection/1` job linkage used by the API.
- Stage certificate/usage projections, eligible schedule updates and the
  COMPLETED transition together. The job coverage links the accepted ledger ID.
- Accept these writes in one completion transaction. Ledger/projection errors,
  refused terminal compare-and-set and completion-commit failures roll back the
  staged acceptance and attempt to mark the already committed job FAILED.
- Roll back failures before the durable context enters too. An initial job
  commit failure must not construct an executor or leave staged RUNNING work to
  be accidentally committed by later daemon cleanup.

An admitted attempt remains metered after an executor or completion failure.
Refused/uncommitted work is not charged. This is existing plan accounting, not
an atomic distributed quota reservation.

A scanner returning error telemetry can still produce a COMPLETED **collection
workflow** with a durable error observation. That is not a successful handshake,
complete coverage, clean crypto posture or confirmed operational outage. A
scanner exception produces FAILED and no accepted probe ledger; a process crash
can leave RUNNING with outcome unknown for the existing reaper/operator flow.
Failure stamping during an actual persistent database outage is still best-effort.

## 4. Honest schedule freshness

Advance an admitted batch's schedules only when telemetry reports all three:

- status `OK` or `PARTIAL`;
- `probed` equals the deduplicated host count;
- `ok` equals the deduplicated host count.

A fully observed weak TLS configuration may legitimately report `PARTIAL`; it
is a fresh observation but not a safe posture. Missing/unknown telemetry,
unreachable targets and incomplete/error probes remain due. Their accepted
ledger still records what the collector returned. The rule is conservative
whole-batch freshness, not per-host partial rescheduling.

The sweep summary retains `due`, `scanned`, `run_id`, `run_ids` and owner groups,
and adds `observed` plus each group's `job_id`. `scanned` counts attempted hosts,
not successful observations. Aggregate status is `OK` only for fully observed
OK batches; other accepted outcomes report `PARTIAL`. No work remains `IDLE`.

## 5. Transaction boundaries and operational implications

The sweep owns its commits and rollbacks and requires committed input without
unrelated pending writes. The
[monitor engine](../../services/worker/worker/monitor/engine.py) now commits
preceding monitor/watch work before entering the network sweep. A network fault
must not roll back those prior results or stamp pending rows under another
owner. The tick also rolls back the session on network-sweep failure so later
sweeps can continue using it.

Each accepted batch remains committed even if a later batch/owner is refused or
fails. The first exception still escapes to the tick's ERROR record and stops
that sweep; remaining work stays due for a later tick. There is no all-fleet
transaction, distributed claim, fairness guarantee or new backoff for persistently
incomplete target rows. A poison first owner can delay later owners: fleet
fairness/retry isolation remains explicit follow-up work.

**Example:** Bank A has 257 due endpoints. The first 256 are admitted, metered,
observed and accepted. An operator then enables emergency stop. The next
one-endpoint batch is refused with no scanner constructed. The first receipt and
its schedule updates remain durable; the final endpoint remains due. Stop is not
retroactively asserted to have interrupted the first batch.

Platform-owned execution remains explicitly unscoped in the existing tenancy
model. This patch does not repair globally unique endpoint/certificate keys or
platform-NULL sharing; those remain A02 isolation work. It does not change BOM
semantics: the ledger remains network evidence for NBOM/CBOM consumers and is
not invented SBOM, TechBOM, HBOM or VBOM coverage.

## 6. Tests and local execution

[Scheduled contract tests](../../services/worker/tests/unit/test_network_sweep_contract.py)
cover refusals without construction/packets, suspended/missing owners, exact-estate
execution, whole-batch quota, committed RUNNING visibility, tenant attribution,
bounded production settings, batching, between-batch stops and schedule reloads,
linked receipts, conservative freshness, storage/completion/CAS faults, and
preservation of prior owners' and prior monitor work.

[Existing sweep tests](../../services/worker/tests/unit/test_network_sweep.py)
now supply actual active tenant registry rows and controlled admission data.
They still assert due selection, grouping, persistence, intervals and exception
visibility; mandatory security checks are not bypassed to retain old fixtures.

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest -q \
  services/worker/tests/unit \
  services/network_scanner/tests \
  services/database/tests \
  services/api/tests/unit/test_network_collection_contract.py \
  services/api/tests/unit/test_scan_admission.py \
  services/api/tests/unit/test_specialized_scan_run_records.py
```

Final local regression on Python 3.11.2: **1,724 passed, 5 skipped,
7 deselected, 139 warnings**, in 250.14 seconds. The **33 scheduled contract
cases** are included, alongside the prior 105 API collection-contract cases.
Changed-Python F/E9 lint, new-file formatting, whitespace and bank-guide
link/JSON/shell syntax checks passed. Existing warning classes remain.
Skips and deselections are not executions; SQLite and controlled/local protocol
fixtures do not qualify PostgreSQL/Neo4j, vendor devices or a bank deployment.
No frontend build, production deployment, migration or workflow change is claimed.

## 7. Next A01 slice

The subsequent [monitor lifecycle delivery](37-network-monitor-lifecycle-isolation.md)
implements trusted owner context in sequential/threaded execution, rollback-safe
status/event persistence and conservative blocked/incomplete freshness. It does
not itself implement phase-specific admission/durable receipts. The subsequent
[bounded monitor phase delivery](38-monitor-network-phase-admission.md) now adds
those for TLS/IPsec/explicit-resolver DNSSEC.
[Explicit bounded TCP monitor discovery](39-bounded-tcp-monitor-discovery.md)
subsequently adds only IPv4 CIDR/port sweeps, with no automatic TLS/plugin
expansion. Unqualified scope/plugins remain refused; do not infer wider parity. Other collectors, distributed enforcement, reaper behavior, exact-estate
schema changes and live operational qualification remain separate obligations.
