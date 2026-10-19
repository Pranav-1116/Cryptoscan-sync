# 38 — Bounded NETWORK monitor phase admission and durable collection

[Guide index](README.md) · [Lifecycle groundwork](37-network-monitor-lifecycle-isolation.md) ·
[Enterprise backlog](33-international-bank-engineering-and-rollout.md)

## Status and important compatibility change

**Implemented locally, 2026-10-19. A01 remains partial.** The NETWORK monitor
engine now admits and durably records these bounded profiles:

- TCP/TLS endpoint collections;
- UDP IPsec/IKE probes of bare IPv4/DNS hosts and explicit validated port sets;
- DNSSEC zone queries through an **explicit IPv4/DNS resolver**, with UDP queries
  and separately admitted TCP transport when zone-transfer checking is enabled;
- mixed collections of those supported profiles.

**Discovery `scope` and nonempty `plugins` monitor configurations are now refused
before constructing an executor.** The enterprise discovery engine expands into
additional destinations, protocols and plugins; it has not been qualified against
this bounded phase contract. Previously accepting a monitor configuration is not
execution permission under the new gate. A scope-only or mixed TLS-plus-scope
monitor becomes BLOCKED; `scan-now` returns 409. No permitted TLS subset runs first.

This intentionally closes an automatic unqualified path rather than silently
continuing it or implying that wrapping TLS qualified discovery. It does not
remove the underlying discovery SDK or qualify other discovery/API/CLI workflows.
Do not switch to another unqualified route merely to bypass a bank policy refusal.

No migrations, workflow changes or historical receipt rewrites are included.
This is local controlled implementation evidence, not bank/device/backend safety
certification or completion of A01 across every scanner.

## 1. Implementation boundary

[network_collection.py](../../services/worker/worker/monitor/network_collection.py)
now prepares a bounded monitor plan and provides an execution context. The
[engine](../../services/worker/worker/monitor/engine.py) applies it under the
persisted owner established in guide 37. The
[network adapter](../../services/worker/worker/monitor/runners.py) re-admits each
phase before its SDK call. The supported worker image already ships API/shared
packages; this reuses the existing
[shared network admission/persistence helpers](../../services/api/api/security/network_collection.py),
not a second weaker policy implementation.

The automatic entry point is `MonitorEngine.run_target`, used by sequential and
threaded daemon execution and the
[authenticated scan-now route](../../services/api/api/routers/monitor.py).
Direct internal adapter/SDK calls and other scanner entry points are not newly
certified by this wrapper. Local UDP protocol fixtures still exercise those SDKs,
not authorization to probe loopback from an automatic monitor.

## 2. Validate the whole plan before any executor

The plan rejects unsupported or unsafe configuration before constructing a scanner,
creating a job, or charging usage:

- 1–256 total logical units: deduplicated TLS endpoints + IPsec hosts + DNS zones;
- finite timeout greater than zero and at most 30 seconds;
- integer worker count 1–32, default 8; default timeout 5 seconds;
- declared expiry-alert horizon retained in the effective profile;
- existing target syntax/SSRF checks applied to TLS, IPsec hosts, DNS zone labels
  and the resolver; a bad member refuses the whole mixed plan, not just itself;
- IPsec hosts must be **bare IPv4/DNS names**. Inline ports and IPv6 forms are
  refused because the current SDK splits host strings and cannot guarantee the
  same IPv6 destination semantics. `ike_ports` contains 1–16 valid numeric ports,
  default `500,4500`; invalid members are not silently replaced by defaults;
- DNS zones have bounded ASCII label syntax. Resolver configuration is explicit;
  machine/environment resolver fallback is not authorized implicitly. IPv6
  resolver forms are refused because this SDK uses AF_INET sockets;
- `check_zone_transfer` must be boolean; its default remains true, so both UDP
  and TCP destinations must be admitted unless the operator explicitly disables it;
- `live=false`, `persist_run=false`, unqualified requested modes and extended TLS
  options are refused. The currently qualified monitor TLS profile is the basic
  handshake, not SNI/STARTTLS/version/cipher/revocation extension qualification.

Unknown non-executable config fields, including a forged `tenant_id`, are not
execution authority or copied into the retained profile. Normalized admitted
inputs and effective settings are retained; the original stored config is not
silently rewritten. Registration and execution remain separate controls.

## 3. Whole-plan admission, then a fresh decision at every phase

Every planned phase passes central active-probe admission before a job is accepted.
This includes emergency stop, admission availability, queue policy, trusted OT
restrictions, existing maintenance-mode rules and exclusions.

The shared helper now distinguishes TCP and UDP and canonical service hints.
Existing API/scheduled TLS callers retain TCP as their default. Service/port
classification is a conservative policy hint, not proof of what listens there.

For DNS, receipts distinguish the **resolver destination** from **zone policy
subjects**. A zone name is a query subject, not a claim that packets connected to
that zone's address. Excluding either the resolver or a queried zone refuses the
whole collection. TCP/AXFR is checked only when configured; UDP-only DNS is not
incorrectly refused merely because TCP is excluded.

Before each actual adapter phase, the execution context:

1. Reloads the current target and tenant registry, checking exact owner, active
   tenant, enabled state and unchanged normalized profile.
2. Re-admits that phase's endpoint/port/protocol/transport intentions.
3. Uses the job repository's guarded RUNNING update to persist its phase receipt.
4. Commits that bounded progress before invoking the phase SDK.

A phase cannot proceed after a refused progress compare-and-set. A stop, pause,
suspension, profile change or exclusion taking effect between phases prevents
later phases from running. This is a **phase boundary**, not an in-flight kill
switch between individual DNS queries, IKE attempts or TLS sockets.

Global policy exclusion lists are private preflight material and are stripped
before tenant-visible admission receipts. The tests assert that another estate's
exclusion names do not leak into the job or ledger.

## 4. Quota and linked durable records

The engine checks the entire logical-unit allowance before any phase starts.
This is existing `scan_run` plan accounting, not a shared connection budget:
one DNS zone is one unit, not the number of DNSKEY/DS/AXFR packets; one IPsec host
is one unit, not the number of attempted UDP ports.

For an admitted plan:

- Commit the owned **RUNNING NETWORK_SCAN job** and admitted attempt meter before
  constructing the scanner. The daemon actor is `monitor-daemon`; `scan-now`
  records the actual authenticated username, never an actor supplied in config.
- Store initial per-phase decisions under
  `cryptoscan.monitor-network-admission/1`, then committed fresh phase receipts.
- Stage an accepted **NetworkScanRun**, `target_kind=monitor`, containing available
  raw phase results and the standard `cryptoscan.network-collection/1` job link.
  The payload's `monitor.target_id` binds it to the persisted watch-list row.
- Accept certificate/usage projections, target-qualified live state/events,
  summary/freshness, job coverage and COMPLETED together in the completion
  transaction. Results and summaries expose `job_id` and `run_id`.
- An executor, storage, phase-progress or terminal-CAS failure rolls back staged
  acceptance and attempts to mark the already committed job FAILED, then writes
  the monitor failure diagnostic/backoff in a clean transaction.

An admitted attempt remains charged if the executor fails or later becomes
blocked. Preflight refusal or a failed initial RUNNING commit has no admitted
meter/job and constructs no executor. A runner that returns blocked **after** its
job was admitted is still an admitted attempt, not a free preflight refusal.

Later-phase failure does not accept a partial ledger for earlier raw results in
this delivery: the job records failure/progress, and no accepted collection ledger
is fabricated. Rich partial archives and crash/reaper recovery remain separate
work. Persistent storage failure can prevent failure stamping; a process crash
can leave RUNNING with outcome unknown. No distributed quota reservation,
exactly-once claim or reaper qualification is implied.

## 5. Completion is not clean crypto or complete coverage

Guide 37's conservative observation rule remains:

- A complete weak TLS or responsive weak IKE observation can be fresh while
  degraded. A completed collection workflow is not safe posture.
- TLS error/incomplete telemetry does not refresh `last_scan_at`.
- DNSSEC retains `observation_complete=false`: its checker can suppress individual
  DNSKEY/DS/AXFR failures. Admission of known destinations does not prove every
  query succeeded or certify a signed/unsigned result as complete coverage.
- Incomplete observations preserve absent prior current evidence, not infer
  deletion. Storage/commit failures restore previous accepted state.

Mixed/non-TLS ledgers do not advertise one TLS subphase's counts/verdict as whole
monitor coverage. Their aggregate status is conservative and aggregate counts
remain unset; available per-phase telemetry is retained under
`monitor.phase_telemetry`. DNS uncertainty cannot be hidden behind a successful
TLS subphase. No synthetic TLS counts are generated for UDP-only collections.

The raw receipt is not proof that every field now maps into NBOM/CBOM materialized
views, and does not invent SBOM, TechBOM, HBOM or VBOM coverage. Six-BOM provenance
and modeled-impact-versus-outage distinctions remain unchanged.

## 6. scan-now, history and retry compatibility

`POST /api/v1/monitor/targets/{id}/scan-now` now:

- preserves existing authentication, role and exact-estate checks;
- returns central refusal codes (409 policy/unsupported, 422 invalid plan,
  429 queue, 402 quota, 503 admission unavailable) instead of HTTP success;
- returns 500 for execution/storage failure with an owned job ID when committed,
  while recording the monitor failure state;
- still returns a normal monitor result for a returned degraded/incomplete
  observation whose collection was durably accepted;
- uses engine whole-plan quota, not the old one-unit NETWORK precheck/double meter.

The existing jobs endpoint exposes the owned job; foreign-bank requests remain
404. Generic repository retry remains 409 for these synchronous NETWORK_SCAN
jobs: resubmit through the authorized monitor route/current persisted profile.
There is no replay of a stale configuration merely by retrying a repository job.

Legacy scanner-wide projection IDs and immutable history remain as described in
guide 37; this delivery does not silently migrate or deduplicate them.

## 7. Practical negative example

A bank monitor requests TLS on `10.0.0.1:443`, IKE on `10.0.0.2` and DNSSEC for
`bank.example` through `10.0.0.53:53`.

If UDP 500 or that DNS resolver is excluded, **none** of those phases starts:
no TLS-only partial execution, no job, no charge. If the whole plan is admitted,
the committed job and phase receipt exist before TLS packets. If stop is engaged
just after TLS, IKE/DNS do not run; the job becomes FAILED, the admitted attempt
remains metered, and the watch-list freshness is unchanged. The earlier in-memory
TLS result is not presented as an accepted full monitor collection.

If all phases return, DNS's current coverage uncertainty still prevents full
freshness even though the workflow and receipt are accepted. This is not proof
of a DNS outage or an operational failure of the bank's payment system.

## 8. Validation and remaining enterprise obligations

The initial new worker contract draft produced **49 failures** against the prior
implementation. Final new controlled suites contain **70 cases**:

- [Worker phase contract](../../services/worker/tests/unit/test_monitor_network_admission.py):
  no-executor refusals, mixed exclusions, SSRF/profile checks, committed RUNNING
  and phase receipt visibility through another SQL connection, authority changes,
  whole-plan quota, stop between phases, failed storage/CAS, mixed coverage,
  initial commit failure and privacy.
- [Authenticated monitor API contract](../../services/api/tests/unit/test_monitor_network_contract.py):
  real bank sessions, trusted actor/owner, forged config owner, foreign/platform
  denial, owned history, retry refusal, correct policy status and failed-job errors.

Existing lifecycle tests retain real SQL failure/rollback assertions. Their
fixtures now supply controlled authoritative admission data, expect admitted
attempt accounting, and target actual COMPLETED commits rather than an obsolete
commit-count position. Internal local UDP fixtures do not bypass an automatic
monitor policy check.

Run with service import roots configured:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest -q \
  services/worker/tests/unit \
  services/network_scanner/tests \
  services/database/tests \
  services/api/tests/unit/test_network_collection_contract.py \
  services/api/tests/unit/test_scan_admission.py \
  services/api/tests/unit/test_specialized_scan_run_records.py \
  services/api/tests/unit/test_monitor_api.py \
  services/api/tests/unit/test_monitor_network_contract.py
```

Final local regression: **1,853 passed, 5 skipped, 7 deselected, 139 warnings**,
in 365.05 seconds on Python 3.11.2. Post-format API/monitor contract validation
passed **175 tests**. Changed-Python F/E9 lint, new/shared-file formatting,
whitespace and bank-guide local-link/JSON/shell syntax checks passed.
Existing warning classes remain; skips and
deselections are not executions. Controlled SQLite/local protocol evidence does
not qualify live PostgreSQL/Neo4j, vendor/runtime or bank deployment. No frontend
build, migration, workflow or production deployment is claimed.

**Still open:** safe discovery expansion/plugin admission; DNS query-level
completeness and richer partial archives; distributed budgets/fairness/claims;
DNS resolution pinning and in-flight stop; granular grants/expiry/region rules;
reaper behavior and other queued/SSH/collector entry points; schema/platform
isolation and live bank/vendor/backend qualification. A01 is not complete.
