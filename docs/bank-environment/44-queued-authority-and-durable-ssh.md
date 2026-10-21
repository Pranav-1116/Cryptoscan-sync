# 44 — Persisted queue authority and durable SSH receipts

[Guide index](README.md) · [Previous qualification ledger](43-a01-a02-qualification-and-open-blockers.md) · [Redis security/HA qualification](45-redis-tls-sentinel-qualification.md)

**Engineering delivery, 2026-10-21. Not a bank deployment certification.**
This increment implements the two queued-authority controls previously recorded
as failing in Guide 43, and replaces the SSH route's response-only result with a
durable job and result ledger. It does not close all A01/A02/A04 rollout gates.
Historical test results in Guide 43 remain historical, not silently revised.

## 1. Why the queued descriptor is not authority

Redis queue messages are delivery hints. A message can be stale, duplicated,
replayed, or written by a compromised producer. A legitimate job ID does not make
its accompanying tenant, target, actor or options trustworthy.

For example, bank A approved artifact `binary:///approved/image`. Replacing its
queued `tenant_id` with bank B, replacing its artifact option, or changing the
actor to `platform_admin` must not select bank B's scope, run a collector, or
mark the real bank A job failed. Otherwise even a rejected forgery becomes an
unauthorized write against a victim's history.

The worker now uses this sequence:

1. Open an internal database read boundary; find the persisted job by ID.
2. Require exact equality of owner, target, branch, commit, initiating actor,
   job type and system ID, plus the persisted `progress.scan_options`.
3. Require the persisted status to be `QUEUED`. Missing, mismatched, running and
   terminal jobs are not eligible descriptors.
4. Replace descriptor progress with a deep copy of **database** progress. Queue
   JSON cannot inject an execution-authority pin, sector or other progress data.
5. Only then enter the persisted job's estate and run existing execution-policy
   admission: stop, passive/OT restrictions, allowed target roots and other gates.
6. Read the job and initiating authority again, then atomically compare-and-set
   its exact ID, owner, version and `QUEUED` status to `RUNNING`.
7. Invoke the selected collector only after the claim commits.

The initial internal read uses `platform_scope()` specifically to resolve the
job. It is not a global weakening of ORM guards, and the collector runs under
`tenant_scope(persisted_owner)`. Platform/unselected work is still NULL-owned;
selecting a bank does not expose platform or another bank's history.

### Refusal behavior

| Condition | Collector | Persisted result |
|---|---|---|
| Foreign owner, changed target/options/actor, unknown ID | Never called | Victim row unchanged |
| Duplicate descriptor after another worker claims RUNNING | Never called | Existing RUNNING execution not failed |
| Matching QUEUED job, revoked authority or refused execution policy | Never called | Best-effort exact-owner, QUEUED-only FAILED stamp |
| Authority database unavailable | Never called | No success invented; refusal stamp may itself be unavailable |
| Valid descriptor, current authority, claim won | Called in persisted estate | RUNNING committed before collection |

A database outage can leave an outstanding QUEUED record; the reaper/operator
must reconcile it. Failure to stamp a refusal never permits collection.

## 2. Fresh initiating authority, not an old username alone

`JobRepository` pins the initiating authority when a new QUEUED row is created.
Both keyword creation and object-form `create(ScanJob(...))`, including
`create_job()`, use this path. The pin lives in existing progress JSON, so this
delivery does not require a schema migration.

At execution the worker derives authority from current SQL records and compares
it with that stored pin. It does not accept a pin supplied in the queue message.

| Initiator | Enqueue pin | Execution check |
|---|---|---|
| Human | User row ID | Same active, non-deleted user; current `scan.trigger` role; active estate; membership with write authority unless a current platform administrator |
| Scheduler human | Underlying user row ID after `scheduler:` normalization | Same fresh human checks, not an implicit system role |
| Named API key | Unique active owned key ID and digest of roles, scopes, methods, IP restrictions and expiry | Same key incarnation, still active/unexpired, same policy digest, current scan-trigger role and active estate |
| Repository monitor (`MONITOR_REPOSITORY`) | Owned enabled repository-configuration ID | Same current configuration for the persisted repository and exact estate |
| Webhook | Owned enabled repository-configuration ID | Same current configuration; conservatively requires both push and PR switches because old jobs lack a pinned event kind |

A renamed/deleted user replaced by another row with the old username cannot
inherit queued work. Revoked/replaced API keys cannot inherit it either.
Ambiguous active API-key names fail closed. Removing bank membership, changing
the member to viewer, disabling a user or suspending the bank prevents execution.
A literal `system` actor is not an administrator bypass. Monitor provenance also
requires the server-produced `MONITOR_REPOSITORY` job type: a human literally
named `monitor` remains a human and cannot inherit configuration authority.
Ambiguous real usernames beginning with reserved `scheduler:` or `apikey:` actor
namespaces fail closed rather than being interpreted as another principal.

### Exact limits of the check

- Human authorization is checked immediately before the claim, not continuously
  inside every collector instruction. There is no atomic distributed revocation
  transaction spanning the user table, job claim and external network packets.
- API-key capture resolves the unique active current key by its persisted actor
  name and owner. This does **not** prove closure of an authentication-to-enqueue
  replacement race: the original authenticated credential ID/path/client IP are
  not carried as immutable request provenance by this delivery. The digest detects
  subsequent policy changes; it does not replay the original HTTP authorization.
- Reserved actor-string collisions require an operator-approved identity/provenance
  remediation; this delivery does not claim a complete typed credential envelope.
- Monitor/webhook authority is the current owned repository configuration, not
  proof of a signed vendor declaration or a region-specific legal grant.
- The existing execution gate still controls target/policy admission. These
  checks do not add positive bank scope grants, DNS pinning, distributed budgets,
  region binding or a bounded in-flight emergency stop.
- SQL compare-and-set prevents duplicate claims of a QUEUED row, not exactly-once
  external side effects or a distributed DB/Redis transaction.

## 3. Producer, retry and upgrade compatibility

The ordinary API producer commits the pinned job before publishing. Subsequent
sector/trace annotations merge progress rather than replacing the pin. Inline
fallback now builds the same descriptor and uses `JobExecutor`; it cannot bypass
persisted reconciliation merely because no queue is configured.

Repository retry creates a **new** job under the current retrier's authority,
carrying the original scan options. It does not resurrect the original user's
expired authority. The database reaper republishes the persisted owner/options
and preserves progress, so an existing pinned job remains eligible only while
its original authority is current. A duplicate re-publication cannot reclaim an
already RUNNING job.

**Legacy unpinned jobs fail closed.** Do not backfill an identity from an old
username and pretend it was captured at enqueue. Before rolling out:

1. Inventory queued work and pause producers/workers through the approved change.
2. Deploy the repository pinning producer and the reconciliating worker together.
3. Reconcile or cancel old queue entries. Resubmit approved legacy work through
   current admission, obtaining a new job ID and a genuine current pin.
4. Inspect refusal reasons and verify no unexpected queue backlog grows.
5. Do not edit old ownership or reset terminal statuses to avoid a refusal.

Direct SQL writers outside `JobRepository` must implement the approved producer
contract or their new unpinned jobs will also be refused. Synchronous specialized
jobs start RUNNING and do not require queued-authority pins.

## 4. SSH: durable attempt before packets

`POST /api/v1/network/ssh-scan` now follows the shared durable network lifecycle:

1. Normalize and bound SSH endpoints; validate targets and initial admission.
2. Commit an exact-owner RUNNING `ScanJob` before invoking host-key or KEX code.
3. Meter the admitted per-host attempt using existing tenant accounting.
4. Recheck admission before **each** host-key phase and, when requested, before
   **each** KEX phase. A stop between phases prevents the later phase.
5. Stage a `NetworkScanRun` with `target_kind=ssh`, findings, SSH telemetry,
   returned TOFU map, initial admission and phase-admission decisions.
6. Commit that result ledger and the job's COMPLETED transition together.
7. Return `job_id` and `run_id` with the result only after durable completion.

A successful response identifies the collection honestly:

```json
{
  "job_id": "<durable-job-id>",
  "run_id": "<stored-network-run-id>",
  "collection": {
    "schema": "cryptoscan.network-collection/1",
    "kind": "ssh",
    "protocol": "ssh",
    "durable": true,
    "coverage": "HOST_KEY_AND_OPTIONAL_KEX_ONLY",
    "baseline_source": "CALLER_SUPPLIED_UNVERIFIED"
  }
}
```

This is an abbreviated shape, not a fabricated result from a bank device. The
actual response also contains findings, telemetry and phase decisions.

### Practical bank A request

Use an already provisioned, authorized bank A session and its normal estate
selection mechanism. No tenant field in this body grants ownership:

```http
POST /api/v1/network/ssh-scan
Content-Type: application/json

{
  "hosts": ["10.21.0.10:22"],
  "timeout": 8,
  "include_kex": true,
  "strict_kex": true,
  "known_host_keys": {}
}
```

Retain the returned IDs, then read:

```text
GET /api/v1/jobs/<job_id>
GET /api/v1/network/runs/<run_id>
GET /api/v1/network/runs?target_kind=ssh
```

The same selected estate can retrieve the stored result after the original HTTP
response is gone. Bank B cannot retrieve bank A's job/run by knowing its ID;
foreign reads remain 404. Platform-unselected history remains NULL-only.

Generic `/jobs/<id>/retry` returns 409 for these synchronous network jobs.
Resubmit the SSH route with its explicit collection profile instead of sending
its target through an unrelated repository pipeline.

## 5. Honest failures and SSH evidence meaning

- Initial receipt creation failure prevents **all** collector calls. An error
  before entering the durable context may propagate as HTTP 500; there is no
  claim that a durable receipt exists when its initial commit failed.
- Collector, ledger or completion failure inside the collection boundary returns
  a generic 503 (admission HTTP refusals retain their policy status). Staged
  result writes roll back and the durable job is best-effort marked FAILED.
- A process crash can leave a visible RUNNING job for reaper reconciliation.
- A finished collection can have a COMPLETED job and FAILED/TIMEOUT observation
  verdict. Completion of recording is **not** a successful SSH connection or a
  healthy cryptographic posture. Findings and `ok=0` remain failures.
- Caller-supplied known-host baselines remain unverified. Storing them does not
  turn TOFU drift into validated device identity or a bank trust anchor.
- The profile observes SSH host keys and optional KEX offers. It does not log in,
  inspect firmware, certify a supplier, or produce TLS certificate evidence.
- Per-host quota checking is not an atomic distributed reservation. The current
  active-job threshold includes this run's RUNNING receipt; an unusually tight
  threshold (for example one) can conservatively refuse its own next phase.

## 6. Tests and source map

Real SQL/auth contract tests use bank A, bank B and platform actors with controlled
collectors, not network packets. They cover forged descriptors, unchanged victim
rows, duplicate claims, post-enqueue revocation/replacement, current monitor/key
identity, inline parity, object-form producer pinning, durable SSH phase refusal,
storage failures, failed observations and owner-only receipt retrieval.

Run from the repository root in the installed test environment:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest -q \
  services/api/tests/unit/test_queue_authority_contract.py \
  services/api/tests/unit/test_ssh_receipt_contract.py \
  services/api/tests/unit/test_broader_admission_qualification.py
```

The final publication-focused run completed **205 passed, 4 warnings** after
adding reserved-name negatives and typed monitor provenance. The restored broad
worker/API run completed **1315 passed, 4 skipped** before that final small
increment; its affected contracts were rerun in the 205-pass run. The earlier
broad run had **1010 passed, 13 failed, 4 skipped**; those failures exposed legacy
routing fixtures and SSH database wiring that were then adapted, not authority
checks weakened. The interrupted broad rerun has no completion claim. The full execution ledger
and Redis evidence are recorded in Guide 45.

Implementation: `db/repositories/{job_repository,queued_authority}.py`,
`worker/core/{queued_authority,job_executor}.py`, `api/routers/trigger.py`,
`api/routers/network.py`, and `api/security/network_collection.py`.

## 7. Six-BOM and historical invariants

SSH can contribute bounded **NBOM** service observations and **CBOM** key/KEX
facts. It does not manufacture **SBOM** package identity, **TechBOM** deployment
relationships, **HBOM** hardware/firmware evidence or **VBOM** supplier assurance.
All six remain distinct. A stored receipt records provenance and outcome; it
neither refreshes old evidence nor rewrites historical ownership. Existing
curated sharing and conservative mixed-estate export/aggregate refusals remain.
