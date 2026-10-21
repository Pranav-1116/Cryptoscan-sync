# 39 — Explicit bounded TCP discovery for NETWORK monitors

[Guide index](README.md) · [Bounded phase contract](38-monitor-network-phase-admission.md) ·
[Enterprise backlog](33-international-bank-engineering-and-rollout.md)

## Status — 2026-10-21

**Implemented locally; A01 remains partial.** NETWORK monitors can now explicitly
opt into IPv4 TCP-connect discovery with `scope_profile: "bounded-tcp"` and
chosen `scope_ports`. This is a new, deliberately narrow profile, not permission
to resume the expanding enterprise discovery pipeline.

Unqualified `scope`, nonempty `plugins`, wildcard/hostname discovery and automatic
TLS/UDP/vendor follow-ups remain blocked. Existing TLS/IPsec/explicit-resolver
DNSSEC profiles retain the [guide 38 contract](38-monitor-network-phase-admission.md).
The combined plan must pass validation, range authorization, central admission
and quota before any executor, job or attempt meter is accepted.

This delivery also separates admission/coverage metadata from observed crypto
in the monitor's live projection, and makes the shared range-authority lookup
**exact estate**, including the platform estate. Readable inventory is not a grant.
No workflow, migration or immutable historical-receipt rewrite is included.

## 1. Why another profile rather than enabling old `scope`

The enterprise engine can expand a scope, perform additional TLS/IKE probes,
invoke vendor plugins and read protocol/configuration/topology data. A wrapper
around one TCP sweep cannot certify those further destinations and operations.
The old automatic monitor path therefore remains refused, rather than running
an admitted TLS subset and discovering later that the rest was forbidden.

The new [scope adapter](../../services/worker/worker/monitor/scope_discovery.py)
uses only [discover_subnet](../../services/network_scanner/network_scanner/discovery/subnet_discoverer.py).
It supplies explicit ports, timeout, workers and `max_targets=256`. A pure scoped
pass does not even construct `NetworkTlsScanner`. The bounded adapter requires
the [engine execution context](../../services/worker/worker/monitor/network_collection.py);
calling it internally without that context does not authorize connections.
Other direct SDK/CLI/API discovery paths are not newly qualified by this work.

## 2. Practical configuration

An operator must first have an enabled, tenant-owned authoritative network scope
covering the requested range, or an applicable registered target under the
existing containment rules. Merely creating a monitor does not establish that
permission. A config `authorization_scope` string or forged `tenant_id` is not
read as authority.

Example monitor-create body, **only for an explicitly approved environment**:

```json
{
  "name": "Approved payment-edge TCP inventory",
  "target_type": "NETWORK",
  "interval_seconds": 600,
  "config": {
    "scope_profile": "bounded-tcp",
    "scope": ["10.40.8.0/30"],
    "scope_ports": [80, 443],
    "timeout": 2.0,
    "workers": 4
  }
}
```

Submit to `POST /api/v1/monitor/targets`; execution is through the normal daemon
or `POST /api/v1/monitor/targets/{id}/scan-now`. Registration is not execution
admission. Without approval of `10.40.8.0/30`, scan-now refuses the pass with 409.

This `/30` has two host candidates. Two ports mean **four TCP socket candidates**,
not two TLS scans. Opening TCP port 443 does not prove TLS, a certificate,
software identity, an algorithm, or quantum readiness.

Static TLS endpoints can be explicitly included in the same config:

```json
{
  "scope_profile": "bounded-tcp",
  "scope": ["10.40.8.0/30"],
  "scope_ports": [80, 443],
  "endpoints": ["10.40.9.10:443"]
}
```

The fifth logical unit is that **declared** TLS endpoint. The adapter never
substitutes the discovered open endpoints into the TLS list. If any initial
member is invalid, unauthorized, excluded or over quota, none of the mixed
plan runs. Successful mixed collections retain phase-specific telemetry; TLS
subphase counts are not presented as whole-plan crypto coverage.

## 3. Bounds before expansion

The preparer enforces:

- IPv4 literal hosts/CIDRs only. Bare hosts canonicalize to `/32`; `/31` has two
  candidates and `/32` one. IPv6, DNS names, wildcards, URLs and vendor discovery
  forms are not supported by this profile.
- The existing discovery SSRF checks: no loopback, link-local/metadata,
  unspecified, multicast or other blocked ranges.
- Explicit `scope_ports`: a list of 1–64 integer TCP ports, 1–65535. Booleans,
  strings and invalid members are refused, not silently replaced with defaults.
  Ports are deduplicated and sorted.
- Canonically identical ranges are deduplicated. Distinct overlapping ranges
  are refused rather than counted twice or silently shrunk.
- At most **256 combined logical units**: TCP candidate host/port pairs plus
  the existing TLS endpoints, IPsec hosts and DNS zones.
- The guide 38 timeout/worker constraints: finite timeout greater than zero and
  at most 30 seconds, default 5; strict integer workers 1–32, default 8.

Candidate size is computed arithmetically **before `hosts()` enumeration**.
That is important because the underlying SDK enumerates before applying its
own cap. A `/24` with one port has 254 candidates; adding two static TLS endpoints
fits exactly. A `/24` with two ports or the first example expanded to `/16` is
refused before a candidate list, executor or job is created.

These are logical socket-call limits, not on-wire packet/QPS limits. TCP retry
behavior, multi-connection protocol SDKs and distributed concurrency are not
bounded by counting these units.

## 4. Permission and fresh receipts

The shared
[range-authority lookup](../../services/api/api/security/scan_admission.py)
now explicitly filters both enabled `ScopeEntry` and `NetworkScanTarget` rows
by `tenant_id == current_tenant()`. This deliberately tightens all callers of
that helper, not just monitors:

| Execution estate | Authority usable for a sweep |
|---|---|
| Bank A | Bank A's enabled scope/registered targets only |
| Bank B | Bank B's enabled scope/registered targets only |
| Platform, no active tenant | Platform-owned NULL-tenant grants only |

Curated NULL-tenant inventory may remain readable under existing inventory
rules; that does **not** make it a bank's execution permission. An unscoped
platform operator no longer obtains every bank's range grants from this helper.
Grant-query failure returns 503; an unapproved range returns 409.

All ranges are validated and authorized during whole-plan preflight. Before
each CIDR SDK call, the execution context then:

1. Reloads the persisted owner, ACTIVE tenant, enabled target and normalized
   configuration. Changed authority/configuration prevents the next range.
2. Rechecks the **executing range's** containment permission and current central
   active-probe policy, TCP/port/service-hint exclusions and intersecting asset
   exclusions. A forbidden member refuses the range, not a silently smaller sweep.
3. Appends a range-specific phase receipt, including `execution_range`, to the
   synchronous RUNNING job through guarded status update and commits it.
4. Only then invokes the TCP sweep.

Range receipts include only that executing range's policy decisions, avoiding
quadratic re-admission and receipt growth across all remaining scopes. Other
configured protocol phases retain their own fresh admission checks; their plan
also rechecks configured scope permissions. Permission changes are checked
between phases/ranges, not during packets already in flight.

The initial accepted job and admitted-attempt meter are committed before probes.
Metering counts **the whole admitted plan**, not measured packets or a refund
for later phases skipped after a stop. For the first example it records four
`scan_run` units, even if a later execution failure prevents acceptance.
This remains a preflight plan check, not an atomic distributed reservation.

## 5. Result acceptance and honest coverage

The adapter verifies returned CIDR, explicit ports, host count, candidate count,
`truncated=false`, distinct open endpoints inside the exact planned socket pairs,
and consistent nonnegative TCP/open counters. Missing/truncated/error/malformed
output or out-of-scope endpoints fail the execution. It does not follow those
endpoints, register them as due-scan targets or accept arbitrary SDK metadata.
Port-derived service/risk hints are omitted from this profile's accepted payload.

A successful durable result retains `scope_discovery` entries with:

- canonical CIDR/ports and candidate/host counts;
- exact open endpoint strings and TCP outcome counters;
- `evidence_kind: "TCP_CONNECT_ONLY"`;
- `tls_status: "NOT_EVALUATED"`.

A pure bounded scope ledger also has verdict `NOT_EVALUATED`, not fabricated
TLS success counts. A valid TCP-only pass can complete its ScanJob while the
monitor remains **DEGRADED**, `observation_complete=false`, and `last_scan_at`
is not refreshed as complete crypto observation. Attempt/completion timing is
available in the job/ledger, not misrepresented as crypto freshness. Static TLS
observations may be retained in mixed runs, but whole-coverage remains partial.

The SDK now treats only an explicit connection refusal as `closed`; local
permission/routing/unknown socket errors remain uncertain (`filtered`). The
legacy `filtered_timeout` aggregate includes such uncertainty: it does not
prove a firewall, an absent host, a remote outage or even that a packet left.

Acceptance is still atomic across the linked NetworkScanRun, monitor status,
certificate/live projections and COMPLETED transition. A late refusal, receipt
failure, SDK exception or bad result retains the FAILED job/admitted meter,
but no accepted batch ledger or staged crypto projection. Earlier in-memory
range outputs in a failed batch are not a newly qualified partial-result archive.
Scan-now surfaces execution failure as 500 with the owned job ID when available;
policy/input refusals retain their specific refusal status.

## 6. Keep the six BOMs distinct

The monitor
[live projection](../../services/worker/worker/monitor/realtime_projection.py)
now excludes `collection`, `monitor`, `scope_discovery`, job and run linkage
metadata from recursive crypto projection. A receipt saying a TLS/TCP phase was
**allowed** is not an observation that TLS/TCP crypto was **used**. Positive
explicit scanner observations elsewhere in the payload remain projectable.

| BOM | Meaning of this delivery |
|---|---|
| NBOM | Bounded transport observations and declared scope provenance; no automatic trusted inventory registration or complete topology claim |
| CBOM | Only explicit protocol-scanner crypto observations; no algorithms/certificates manufactured from port numbers or admission labels |
| SBOM | No package/version inventory inferred from an open socket |
| TechBOM | No verified application, OS, framework or product identity inferred from service-port conventions |
| HBOM | No chassis, processor, HSM or hardware capability claim from TCP reachability |
| VBOM | No vulnerability/patch verdict inferred from an open, closed or uncertain port |

Raw admission/linkage evidence remains in the durable ledger. This filter applies
to newly projected passes; it does not retroactively certify, rewrite or silently
repair historical receipts/snapshots. Any repair of an older materialization
requires an audited provenance review, not blanket deletion of TLS facts.

## 7. Controlled evidence and remaining qualification

New controlled suites:

- [57 worker cases](../../services/worker/tests/unit/test_monitor_scope_discovery.py):
  whole-plan refusals, bounds before enumeration, exact socket membership,
  forged/truncated result rejection, late stop/revocation/pause/suspension/config
  changes, receipt compare-and-set/commit faults, admitted failure metering,
  fixed TLS versus discovery follow-up, actual TCP SDK with controlled probes,
  range-local receipts and prevention of receipt-derived crypto observations.
- [14 authenticated API cases](../../services/api/tests/unit/test_monitor_scope_contract.py):
  actual SQL grants and session authentication, actor/job linkage, foreign monitor
  denial, disabled/foreign/platform grants (both scope and registered targets),
  forged config authority, bank-private job/run reads, synchronous retry refusal,
  explicit refusal statuses and owned failed-job responses.

Local Python 3.11.2 execution on the final source tree: **1,924 passed, 5 skipped,
7 deselected, 139 warnings** in 462.20 seconds. This selects worker unit tests,
network-scanner and SQL database tests, and six API contract/admission/monitor
modules. The 71 new scope cases also passed together after formatting. Existing
warning classes remain; skips/deselections are not executions. Local
Python/SQLite/controlled protocol fixtures are not bank, vendor, PostgreSQL,
Neo4j or production certification. No frontend or live deployment is claimed.

Reproduction from the repository root with root requirements installed:

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
  services/api/tests/unit/test_monitor_network_contract.py \
  services/api/tests/unit/test_monitor_scope_contract.py
```

Changed-Python F/E9 lint, new-file/profile formatting, whitespace and bank-guide
local-link/JSON/shell syntax checks passed. Workflows, migrations and main are
unchanged; publication uses `[skip ci]`, not a workflow edit.

Open work includes enterprise/plugin/SSH/queued entry-point qualification,
versioned granular grant evidence, expiry/region/window semantics, distributed
reservation/fairness, packet/QPS budgets, in-flight stop, complete partial-result
archives and deployment qualification. Generic platform-operator job/run-history
visibility is not newly hardened by this profile; platform callers are denied
execution of bank monitors, and bank-to-bank history is tested. Broader
platform-estate history isolation remains a separate A02 review. **A01 remains
partial.**
