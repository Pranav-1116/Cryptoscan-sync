# 24 — Operational dependency modes and conditional outcomes

**Implemented step 8, 18 October 2026.** Dependency reachability is not a failure
model. A recorded call can be essential, optional, failover-dependent or buffered;
those are different operational declarations. Missing declarations remain unknown.

[Guide index](README.md) · [Ten-step status](../dev/dependency-intelligence-roadmap.md)

## 1. What changes, and what does not

A `SystemDependency` can now carry a bounded `operational_dependency` JSON
assertion. New evaluations expose `cryptoscan.operational-impact/1`, using
per-edge `cryptoscan.operational-dependency/1` conditions. The shared projection
is used by unified cascade, the memory graph and selected native graph reads.

Operational mode is **orthogonal to** relationship type, lifecycle, provenance
and system classification:

- `CALLS`/`IMPORTS`/`IMPORTS_CRYPTO`/`DEPENDS_ON` still govern modeled propagation.
- Current/uncertain/terminal lifecycle rules are unchanged.
- Direct exposure, dependent consumers and supporting context retain their
  disjoint meanings and counts.
- Optional, failover and buffered edges are **not removed from exposure**.
- A source pattern, `BACKS_UP` label, process role such as `PRIMARY`, general
  confidence value or recent confirmation does not establish operational mode.
- The analysis does not assume the provider actually becomes unavailable.

The feature does not predict whole-system outages, compute a failure probability,
or assert that a transaction survives. It preserves a conditional interpretation
for each declaration rather than collapsing a mixed dependency chain into one
availability verdict.

## 2. The five modes

| Mode | Conditional interpretation | What remains unknown |
|---|---|---|
| `UNKNOWN` | Operational consequence not established | Missing, explicitly unknown or malformed input must not default to hard failure or safe operation |
| `HARD` | If the provider is unavailable to the relevant function, the declared required dependency may block that function | Actual invocation, scope of the function, timeouts and whole-consumer outcome |
| `OPTIONAL` | Provider disruption may degrade the declared optional function | Whether core service really continues, fallback behavior and feature criticality |
| `FAILOVER` | Continuity depends on successful routing/switchover to alternatives | Current alternative health, independence, capacity, configuration, credentials/trust and tested switchover |
| `ASYNC_BUFFERED` | Buffering may defer consumer disruption while the provider is unavailable | Current headroom/backlog, arrival/drain rates, durability, retention behavior and recovery/replay |

Every condition reports `verified=false`, `failure_probability=null` and
`safe_delay_seconds=null`. These are intentional unknowns, not omitted computed
results. An operational evidence pointer is retained but not independently
verified by this evaluation.

## 3. Assertion fields and examples

Supported input fields are `mode`, up to 20 bounded `assumptions`, an optional
operational `evidence_ref`, and mode-specific declarations:

- `failover_system_ids`: at most 20 distinct exact raw system IDs, only for
  `FAILOVER`. Write-time lookup is restricted to the selected estate. Names,
  graph-prefixed IDs, unknown/foreign IDs and consumer/provider self-references
  are not accepted as alternatives.
- `buffer_capacity_messages`: integer from zero to the JSON-safe integer maximum,
  only for `ASYNC_BUFFERED`. Zero is a valid declared capacity, not “missing”.
- `buffer_retention_seconds`: finite positive number within the JSON-safe bound,
  only for `ASYNC_BUFFERED`.

Extra fields, unsupported modes, duplicate alternatives, incompatible mode
fields, negative/fractional/boolean capacities and nonfinite/zero retention are
rejected on API writes. Defensive readers convert malformed legacy/native
assertions to `UNKNOWN` with `assertion_status=INVALID`; they do not invent a hard
mode. Absence is `UNSPECIFIED`, distinct from an explicit declared `UNKNOWN`.

Example failover declaration (use real IDs from the authorized estate):

```json
{
  "mode": "FAILOVER",
  "failover_system_ids": ["payments-hsm-standby"],
  "evidence_ref": "bank-test/PKI-2026-10",
  "assumptions": [
    "Routing configuration includes the standby",
    "Independent capacity and trust configuration require bank validation"
  ]
}
```

A loaded alternative ID establishes inventory identity only. It does not create
an alternative dependency edge, expand system/process exposure or prove a
working route. Read-time unresolved alternatives are labeled **not in the loaded
registry**, not falsely called nonexistent. Native reads look up only the
referenced identities within the current tenant partition; they do not export
the entire graph to infer alternatives.

Example buffered declaration:

```json
{
  "mode": "ASYNC_BUFFERED",
  "buffer_capacity_messages": 10000,
  "buffer_retention_seconds": 3600,
  "evidence_ref": "queue-config/payments-17",
  "assumptions": ["Queue durability and recovery/replay require validation"]
}
```

Neither 10,000 messages nor 3,600 seconds is a verified safe outage window.
Capacity is not current free space; retention is not tolerated outage duration.
No arithmetic converts these declarations into a time-to-impact guarantee.

## 4. Write and audit workflow

`POST /api/v1/graph/edges` accepts an optional `operational_dependency` alongside
existing relationship/provenance/lifecycle fields. Omitting it preserves the
unknown legacy meaning. Alternative identities are checked **before** insertion,
so a rejected request cannot leave an edge to be committed by later work.

Existing edges can be annotated with:

`PATCH /api/v1/graph/edges/{parent_id}/{child_id}/operational-dependency`

```json
{
  "expected_revision": 3,
  "operational_dependency": {
    "mode": "OPTIONAL",
    "evidence_ref": "service-contract/analytics-4",
    "assumptions": ["This call supports optional analytics only"]
  },
  "reason": "Approved operational dependency review",
  "evidence_ref": "change/BANK-804"
}
```

The outer reference explains the **change**; the nested reference supports the
**mode assertion**. They may cite the same approved material but have different
meanings. General relationship evidence is not silently promoted into proof of
an operational mode.

The patch requires an authorized writer, exact owned endpoints, manual lifecycle
source ownership and a current expected revision. Collector-owned edges must go
through the existing audited source-claim workflow first. Terminal
`DELETED`/`SUPERSEDED` edges cannot be edited. Revision conflicts are `409`;
foreign/missing identities are not disclosed through a different lookup path.

Updates increment the existing lifecycle revision and append a lifecycle audit
event containing the operational assertion **before and after**. They do not
refresh observation/confirmation/verification timestamps, extend expiry or
reactivate stale/expired links. `operational_dependency=null` explicitly withdraws
an assertion and returns it to unknown. A partial graph payload that omits the
field does not silently clear an existing annotation; explicit null clearing
and lower-revision guards work in both adapters.

The edge manager supplies mode, assumptions, evidence and relevant alternative/
buffer fields. Existing manual-owned edges have an “Edit mode” action requiring
change reason/evidence and the loaded revision. Collector-owned/terminal edits
are disabled; the server enforces these boundaries independently.

## 5. Projection scope, explanations and bounds

Unified cascade returns `impact.operational_impact`. Graph business-impact returns
`operational_impact`; graph simulate/explain carry it through. Traversal witnesses
also retain the mode declaration and its conditional interpretation per edge.
Stored historical answers are never enriched from today's inventory.

The reducer examines **all loaded current propagating system-edge records whose
endpoints both lie in the classified review scope**. It is not restricted to the
one minimum-hop witness chosen for display. A second path can therefore retain
an optional/buffered declaration even when a displayed shortest path uses a hard
edge. Supporting-context endpoints retain that scope label; their mode does not
make them exposed consumers.

Counts describe loaded assertion-record variants, deduplicating identical rows;
conflicting variants are not silently resolved by first-row selection. At most
500 detailed records are returned, with a full loaded count and truncation flag.
The console previews 20 records. Neither bound changes mode counts or system/
process classification. Non-current records **within this review subgraph** are
counted separately and do not supply active conditions. This is not a whole-estate
stale-record count or a complete dependency-coverage claim.

The response carries relationship evidence separately from operational evidence,
retaining actual source/pointers/lifecycle/timestamp meaning. Missing mode,
assumptions, evidence, alternatives and queue declarations remain visible gaps.
Source coverage is carried when supplied; missing source metadata remains unknown.

This does **not** solve correlated failures, hard/optional AND/OR service logic,
quorum, traffic load balancing, capacity simulation, recovery ordering or queue
exhaustion. No alternate edges or runtime measurements are synthesized to fill
those gaps.

## 6. History, replay and watches

New stored runs freeze the mode declarations and interpretations with the
captured inventory/clock. Captured-version replay uses that captured assertion,
not the current SQL annotation. Older results without this schema remain
operationally unclassified; they are not retroactively assigned hard or unknown
counts as if those had been analyzed then.

History diffs include `operational_comparison`. Comparable canonical target,
relationship policy/classification and current operational schema are required.
If either detailed listing is truncated, the comparison is unavailable rather
than reconstructed from a bounded preview. Added/removed assertion records and
changed declaration signatures are separate from exposure-membership changes;
clock-only freshness differences are not declaration changes.

Watches can report `operational_conditions_changed` even if the review union is
unchanged. This emits a declaration-change event, **not an availability or outage
event**. Legacy/incomparable/truncated operational projections do not yield false
mode-change claims. Existing unresolved target/baseline guards still apply.
Failover health and actual queue headroom are not monitored by this feature.

## 7. Bank example you can run locally

From the checkout root, with backend dependencies installed:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:)"
python - <<'PY'
from datetime import datetime, timezone
from cbom.unified_cascade import unified_cascade
estate = {
    'systems': [{'id': s} for s in ['signing', 'channel', 'analytics', 'queue', 'standby']],
    'dependencies': [
        {'source': 'channel', 'target': 'signing', 'type': 'CALLS',
         'operational_dependency': {'mode': 'FAILOVER', 'failover_system_ids': ['standby']}},
        {'source': 'analytics', 'target': 'signing', 'type': 'CALLS',
         'operational_dependency': {'mode': 'OPTIONAL'}},
        {'source': 'queue', 'target': 'signing', 'type': 'DEPENDS_ON',
         'operational_dependency': {'mode': 'ASYNC_BUFFERED', 'buffer_capacity_messages': 1000}}]}
result = unified_cascade(estate, target='signing', kind='system',
                         now=datetime(2026, 10, 18, tzinfo=timezone.utc))
assert result['impact']['system_classification']['exposure_system_count'] == 4
assert 'standby' not in result['impact']['affected_systems']
op = result['impact']['operational_impact']
assert op['mode_counts']['FAILOVER'] == op['mode_counts']['OPTIONAL'] == op['mode_counts']['ASYNC_BUFFERED'] == 1
assert all(e['condition']['verified'] is False for e in op['edges'])
assert all(e['condition']['safe_delay_seconds'] is None for e in op['edges'])
print('Four systems remain in exposure review; three distinct conditional modes; no failure forecast.')
PY
```

## 8. Deployment and qualification

**Apply migration `0101` before deploying these API/worker model readers.** It adds
a nullable JSON column and does not backfill an invented operational mode. The
SQLite upgrade/downgrade test preserves a legacy edge; downgrading removes the
new assertion column, so retain approved evidence/backups before rollback.
Earlier lifecycle/evidence migrations remain prerequisites.

Local checks cover strict schema negatives, unknown legacy metadata, alternative
identity/tenant/role denial, revision/source/terminal guards, audit before/after,
non-refreshing edits, mode-only history/watch changes, frozen replay, all-mode
memory/Bolt-double/unified behavior, explicit clear/partial omission/lower revision,
selected native reads without export, lifecycle exclusion, and bounded details.
Console tests cover mode editing, unknown legacy answers, conditional failover,
zero queue capacity and truncation warnings. Final counts are recorded in the
[ten-step status](../dev/dependency-intelligence-roadmap.md).

The Bolt double dispatches tagged queries; it does **not execute Cypher**. These
checks do not certify production PostgreSQL/Neo4j, runtime availability, queue
capacity, genuine failover independence or complete bank authorization. Steps
**9–10 remain pending**: comprehensive coverage/truncation presentation and
bank-specific negative/backend qualification. NBOM, CBOM, SBOM, TechBOM, HBOM and
VBOM continue to represent different evidence, not interchangeable runtime proof.
