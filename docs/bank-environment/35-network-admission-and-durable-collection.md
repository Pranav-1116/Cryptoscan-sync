# 35 — A01 first delivery: API network admission and durable collection

[Guide index](README.md) · [Enterprise backlog](33-international-bank-engineering-and-rollout.md) ·
[Failure register](32-bank-scan-failure-modes-and-qualification.md)

## Status and scope

This is an **implemented first slice of A01**, not closure of the entire
international-bank backlog. It replaces the network API route differences
recorded at planning commit `f901b775` for these operations:

- `POST /api/v1/network/scan`.
- `POST /api/v1/network-scans` and its trailing-slash alias.
- `POST /api/v1/network/run-due`.
- `POST /api/v1/network/discover`, including its optional TLS phase.

The shared implementation is
[network_collection.py](../../services/api/api/security/network_collection.py).
No migration is needed. Existing stored answers are not rewritten.

**Not certified here:** a bank deployment, actual PostgreSQL/Neo4j, a distributed
scheduler, physical device safety, regional federation or vendor adapters.

## 1. Defects reproduced before the fixes

Real-session bank tests, with only external executors and admission data seams
controlled, reproduced missing direct-route admission, missing alias/discovery
probe-ledger writes, endpoint/exclusion mismatches and shared scheduled-target
selection. The original 66-case test draft produced 49 failures and 17 passes.
The suite was subsequently expanded as transaction and compatibility cases were
added. This is local implementation evidence, not a bank incident report.

Previously, `persist_run=false` could deliberately avoid a ledger record and a
storage error could still accompany a successful HTTP response. An accepted
alias scan had a durable job but not the NBOM's probe result ledger. Those
behaviors cannot establish a durable end-to-end collection receipt.

## 2. Shared preflight, then execution

The four API paths now use the same helpers to:

1. Resolve authenticated tenant context and keep it active through synchronous
   handler execution. Async request-task scoping avoids relying on ContextVar
   changes made inside a separate sync dependency thread.
2. Validate and normalize the whole host batch before starting any executor.
3. Check central admission for the target/port/collector phase: emergency stop,
   admission availability, queue policy, mode and trusted OT policy.
4. Apply exclusions to normalized host/endpoint/IP/CIDR forms, port, transport
   and service-profile hints. A sweep intersecting an excluded address/scope is
   refused as a whole, not silently shrunk after probing it.
5. Check the existing plan allowance for the whole deduplicated TLS batch.
6. Commit an owned RUNNING job with the initial admission decision before
   external collection starts.

Port classification is a conservative policy hint, not proof that a port is
actually running HTTPS/SSH/etc. No DNS/service discovery is performed to classify
it. This work does **not** add DNS pinning or a new general destination-grant
system. Direct-host permission remains subject to existing role/target policy
and bank network controls; a submitted host is not a legal authorization.

The central maintenance policy is preserved, including its existing IT-mode
behavior. This change does not invent a stricter global maintenance-window rule
or certify per-device active/passive safety profiles.

## 3. Linked durable records and honest failures

The run has two linked records:

- **ScanJob:** authenticated actor, tenant, RUNNING/COMPLETED/FAILED state,
  admission, timing and bounded execution summary.
- **NetworkScanRun:** accepted result payload, telemetry and a versioned
  `collection` object containing the linked job ID and collection kind.

Successful responses include both `job_id` and `run_id`. Admitted request
profiles (including effective worker count) are retained without unknown body
fields. Whole global exclusion lists are used only inside server preflight,
not copied into tenant-visible receipts. Job coverage contains
`network_run_id`; it is not a second copy of the full finding payload.

Ledger writes, certificate/usage projections, successful due-schedule updates
and COMPLETED transition are committed together. Insert/commit failures are not
swallowed as successful scans. The transaction is rolled back before attempting
a separate FAILED job transition. A refused completion compare-and-set raises
instead of committing a success receipt anyway.

The initial RUNNING record is committed separately so an executor crash can
leave an explicit unknown/in-flight attempt rather than no record. If the DB is
unavailable, even failure stamping may be impossible; the code cannot promise
an acknowledged FAILED row during total storage loss. Existing reaper/recovery
controls still require operational qualification.

`COMPLETED` means the collection workflow finished and its result was accepted.
It does **not** mean every probe succeeded, the posture is safe or the estate is
complete. FAILED/PARTIAL/error telemetry and missing fields remain visible.

## 4. Discovery is a separate phase, not permission for future TLS

Discovery still requires execution-time CIDR authorization. Its selected ports
are admitted before any sweep. Returned endpoints are revalidated and checked
against the admitted network. Before optional TLS collection, policy is checked
again; an intervening stop prevents TLS. The successful TLS receipt retains its
own phase admission alongside the initial TCP job admission.

Registration is also deferred until the required checks and is transactional.
A stop after the sweep must not silently add targets or start TLS. A rejected
second phase leaves a FAILED job, not a successful TLS observation. This slice
does not promise independently accepted partial-result archives after every
failed later phase; source completeness and richer partial receipts remain A06.

A discovery-only result is stored with `target_kind=discovery`, no fabricated
TLS telemetry and `probe_status=NOT_EVALUATED`. A discovery-plus-TLS result uses
`discovery_tls` and preserves both the discovery payload and TLS observations.
A discovered/open port by itself is never upgraded into an observed TLS claim.

## 5. Due rotation and freshness

An API caller selects **exactly its current estate's scheduled targets**.
Shared platform inventory does not grant a bank authority to execute or advance
platform-owned schedules. An unscoped platform caller likewise selects the
platform schedule namespace, not every bank implicitly.

A failed/incompletely observed batch remains due. A fully observed batch can
advance when every requested probe is successful, even if posture findings make
the telemetry PARTIAL. Weak cryptography is a fresh adverse observation, not a
reason to retry-spin indefinitely. This conservative implementation does not
advance only the successful members of an otherwise failed batch; future
scheduling/backoff work must address that repeated-work cost.

These rules concern the **API due route**. They do not assert that the separate
worker monitor/scheduler has been moved to the same contract in this delivery.

## 6. Compatibility changes operators must review

- Active host routes reject `live=false` with 422 rather than ignoring it and
  sending active traffic. Offline filesystem collection is a different path.
- Direct host scans reject `persist_run=false` with 422. Durable recording is
  mandatory for these live API collections.
- Host lists require 1–256 entries; normalized duplicates are collected/metered
  once. Larger due/TLS follow-up batches must be split, not silently truncated.
- Timeout must be finite, greater than zero and at most 30 seconds. Explicit
  worker counts are 1–32; API default is 8. Discovery accepts at most 64 selected
  ports, each 1–65535. These are local request bounds, **not** a proven QPS,
  total-connection or distributed concurrency reservation.
- Missing required/invalid request values are validation failures before traffic.
- Storage failures return an error, not the old best-effort successful response.
- All four TLS API paths use the existing per-host plan accounting. Batch checks
  include the requested host count; they are not atomic distributed reservations.
  Admitted attempts may consume allowance even when a later collector fails.
- Generic `POST /api/v1/jobs/{id}/retry` refuses these synchronous network jobs with
  409: a repository retry cannot reproduce their admitted profile. Resubmit an
  authorized request to the original network route instead.

Review clients relying on the old response/error behavior before rollout.
No legacy history is recomputed or silently assigned to a new tenant.

## 7. Local verification

[Bank collection tests](../../services/api/tests/unit/test_network_collection_contract.py)
use actual sessions, DB roles, middleware/context resolution and SQLite writes.
They cover denial without packets/side effects, mixed batches, wrong scope,
foreign schedules, quotas, profile validation, owned ledger/job links, phase
stops, registry exclusions, insert/final-commit failures, refused completion,
partial/error freshness and safe retry behavior. No real bank is contacted.

Related fixtures now use real SQL sessions for mandatory durable records rather
than plain `object()` sessions. Legacy expectations for optional persistence and
successful storage errors were replaced with the stricter contract. A historical
TLS-to-NBOM assertion was updated to include the already-supported exact
certificate fingerprint; no production fingerprint semantics were weakened.

Run with repository requirements and the service import paths configured:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest -q \
  services/api/tests/unit/test_network_collection_contract.py \
  services/api/tests/unit/test_network_run_persistence.py \
  services/api/tests/unit/test_network_scan_guard.py \
  services/api/tests/unit/test_scan_admission.py \
  services/api/tests/unit/test_specialized_scan_run_records.py
```

## 8. What is still open

A01 remains **partially delivered**. The subsequent
[scheduled TLS worker delivery](36-worker-scheduled-tls-admission.md) extends this
contract to the leader-worker `network_scan_targets` rotation. Next
qualify/migrate the separate `monitor_targets` network runner. Its
[owner/rollback/freshness groundwork](37-network-monitor-lifecycle-isolation.md)
is now implemented, followed by [bounded phase admission/receipts](38-monitor-network-phase-admission.md)
for TLS/IPsec/explicit-resolver DNSSEC. The subsequent
[bounded TCP monitor discovery](39-bounded-tcp-monitor-discovery.md) qualifies
only explicit IPv4 CIDR/port sweeps without dynamic follow-up; shared range grants
are now exact estate. Expanding scope/plugins remain refused. Also pending are
inventory plugins, full retry/reaper/side-effect recovery and remaining non-API
execution profiles. [SSH durable receipts and queued authority](44-queued-authority-and-durable-ssh.md)
are now implemented locally; that does not qualify all live devices or protocols. Current direct-host role/grant policy, region/legal-
entity restrictions, platform-inventory sharing and export boundaries remain
separate A02/A04/A13 obligations. Do not infer their closure from these tests.

A05/A12 still need policy-budget enforcement at actual connections, distributed
reservations/fairness, per-device profiles, bounded in-flight stop and load
qualification. A06/A07 still need richer partial/completeness receipts and real
backend/operational fault evidence. DNS/time-of-use, vendor permission, parser
runtime and physical bank controls must not be treated as solved by API parity.


## Local execution record — 2026-10-19

Python 3.11.2. Final scoped backend regression: **3,467 passed, 17 skipped,
14 deselected** in 407.86 seconds. This covered shared models, control plane,
network scanner, worker, CBOM, database, graph and the selected network/dependency/
twin/security API suites. A supplementary binary-scan/event/documentation run
passed **36 tests**. The new bank collection-contract module contains **105
cases**, all selected in the scoped regression.

Changed Python F/E9 lint, new-file formatting, whitespace and bank documentation
checks passed. Existing warning classes remain. No live bank, live PostgreSQL/
Neo4j, production runtime, frontend build, migration or workflow change is claimed.
The controlled local TLS harness is protocol-test evidence, not supplier or bank
qualification. Skips/deselections are not successful executions.
