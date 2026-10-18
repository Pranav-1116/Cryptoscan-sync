# 25. Coverage, truncation and missing-link qualifications

[Bank guide index](README.md) · [Implementation roadmap](../dev/dependency-intelligence-roadmap.md) ·
[Classified scope](17-classified-system-scope.md) ·
[Exact identities](23-exact-target-identities-and-ambiguity.md) ·
[Operational dependency modes](24-operational-dependency-modes-and-conditional-outcomes.md)

## What Step 9 changes

New unified cascade answers carry `cryptoscan.analysis-coverage/1`. Snapshot
capture carries `cryptoscan.source-coverage/1` read metadata. The console shows
**Coverage and limitations before impact panels**, including unresolved target
answers. History lists summarize frozen coverage; diffs and watches gate impact
change claims on compatible input coverage.

This is an additive qualification, not a new exposure classifier or failure
simulator. Direct exposure, dependent consumers and supporting context retain
their existing disjoint memberships. Explanation caps never shrink compact
membership counts. Existing historical answers are not rewritten.

**An absent link, omitted row or unknown total is not zero exposure or evidence
of safety.** Even `BOUNDED_REVIEW` leaves `estate_completeness: UNKNOWN`. There is
no overall percentage, automatic bank-readiness pass, or discovery certificate.

## Four independent questions, not one denominator

| Qualification | Meaning | What it does not establish |
|---|---|---|
| Source collection | Returned rows, configured limit, actual truncation, observed lower bound and any known query total | Complete discovery across the bank or source correctness |
| Traversal horizon | Direction, scope, depth and whether eligible loaded adjacency continues beyond the horizon | Every real dependency or runtime failure |
| Explanation/list bounds | Bounded seeds, witness paths, process reasons, operational details, candidate lists and evidence references | Smaller modeled membership when a detail is omitted |
| Missing-link/assertion checks | Scoped gaps such as unmapped processes, unresolved system references, missing endpoint ownership and unknown operational modes | Unregistered systems, healthy systems, or measured outage probabilities |

SBOM, NBOM, CBOM, TechBOM, HBOM and VBOM remain separate evidence layers. An NBOM
endpoint without a loaded registry owner does not prove an application is
unregistered. A package in an SBOM does not create a deployment assertion. HBOM
inventory without a crypto-hardware link does not prove no application uses the
device. VBOM supply relationships do not turn into system-to-system execution.

Do not add a component count to a dependency-row count or divide process links
by endpoints. Repeated edges in separate returned witnesses are explicitly
reported as **path-edge occurrences**, not unique estate edges.

## Actual source truncation: cap plus one

The twin adapter applies stable ordering and requests at most `limit + 1`
collection rows. It returns only the first `limit`; the extra row is a sentinel.
For example, with a dependency limit of 2:

| Query observation | Returned | Truncated | Observed lower bound | Exact total |
|---|---:|---|---:|---|
| Two rows, no sentinel | 2 | false | 2 | Not asserted by this read metadata |
| Three rows including sentinel | 2 | true | 3 | Unknown, not fabricated as 3 |
| Zero limit, one sentinel | 0 | true | 1 | Unknown, not zero exposure |

A representative collection fragment is:

```json
{
  "returned": 2,
  "limit": 2,
  "truncated": true,
  "known_total": null,
  "observed_lower_bound": 3,
  "unit": "rows",
  "status": "TRUNCATED",
  "scope": "authorized query only; not proof of complete discovery"
}
```

Current twin limits include assets 20,000, systems 20,000, dependency rows
50,000, network scan runs 2,000, and unique observed raw endpoint keys 20,000.
Registered endpoints have their own 20,000-row bound. Evidence uses up to
20,000 **evidence/system pairs**, not 20,000 unique findings. System-asset,
system-vendor, certificate-usage, process/support, vendor, hardware and declared
crypto-link reads carry their own metadata. See `SNAPSHOT_CAPS` in the
[twin adapter](../../services/api/api/routers/digital_twin.py) for each bound.

Software inventory separately reports limits and authorized query totals:
2,000 artifacts, 5,000 deployments, 200 release/SBOM bindings and 20,000
components. Components have component units; the other collections have row
units. Hitting the component budget can also omit binding rows. This is shown
separately instead of being hidden inside a package match result.

For network observations, newest run wins for each raw endpoint key, with a
stable ID tie-break. Duplicate keys do not consume another endpoint slot. Run
metadata counts rows read, not runs whose every probe was projected; the
endpoint qualification separately reports omissions during projection. A run
sentinel only proves another run exists, not another unique endpoint.

The selected graph-snapshot dependency fallback reports a known total for its
eligible-shaped edge rows because that JSON document has already been loaded.
It is not unioned with relational dependencies. A zero dependency budget with
known relational omissions must not activate the fallback and hide truncation.

**Resource boundary:** these are result/read qualifications, not a load-test
certificate. A graph snapshot or scan-run JSON value can still be large before
its projected rows are capped. Query consistency across concurrent writes,
PostgreSQL performance, and maximum tenant data sizes need deployment testing.

## Traversal limits: loaded horizon versus unknown extension

For unified cascades and the in-memory graph engine, the coverage probe uses
the same seeds, registry, clock, relation policy, direction and hop bound as
the corresponding walk. Current System-to-System propagation excludes terminal,
stale and context relationships. Potential-link probes are separately labelled
and also include potential direct seeds; potential reachability is not active
exposure. Target adapters that intentionally omit forward context do not gain
an active forward walk merely because coverage is displayed.

At the horizon, the probe counts distinct eligible next-hop neighbours not
already reached. A cycle back to a seed, an already visited node, duplicate
edges, a context edge, or an endpoint outside the loaded system registry is
not an omitted known system. The probe does not append systems to impact lists.
Its neighbour count covers one further loaded adjacency, **not all transitive
systems beyond the horizon**. Vendor-of-vendor traversal has a separate
three-hop qualification with vendor units.

Native graph walks expose their selected depth but do not perform a new
extension query. Their answer explicitly includes:

```json
{
  "extension_check": "NOT_EVALUATED",
  "more_loaded_systems": null,
  "unvisited_neighbour_count": null
}
```

Unknown extension is not converted to `false` or `0`, even for an empty selected
result. Native coverage does not export and recompute the entire graph. Collector
truncation flags are retained where available, while absent collector totals
remain unknown. Native selected-query doubles are not live Cypher qualification.

## Missing linkage and bounded explanations

Coverage keeps separate entries for:

- Requested review/potential systems without recorded process support and
  unresolved/invalid process links. Missing metrics remain unknown, not zero loss.
- Propagating dependency records whose endpoints are not both in the loaded
  system registry. Explicit non-system context prefixes are excluded from this
  system-reference check. Capped registry reads may explain unresolved references.
- Loaded endpoint projection records without a loaded system owner and loaded
  crypto assets without a loaded system linkage.
- Selected certificate equal-subject endpoints lacking a usable fingerprint and
  selected certificates without exact loaded ownership. Subject equality does
  not become a certificate binding.
- Selected devices without crypto linkage, software artifacts without binding
  to active deployment context, and unlinked selected deployments.
- Loaded vendor assertion rows with references absent from the loaded vendor
  registry. External intermediate IDs remain traversable by the vendor adapter.
- Unknown operational modes among loaded current review-edge assertion variants.
  An unknown mode is not a hard dependency or an outage prediction.
- Evidence missing from returned path-edge occurrences, and missing selected
  witnesses. This does not claim a graph-wide evidence audit.

Not-assessed/not-applicable checks retain null counts. Positive gap counts are
shown prominently with their own scope and denominator where meaningful. Gap
counts from different scopes are not summed into an overall score.

Detail qualifications include 500 seeds/witnesses per group, 500 process
details, 200 reasons per process, 500 operational edge details, 20 context
records per seed, and 50 evidence references per returned path edge. Certificate
subject-only detail lists have a separate 200-entry cap. Process ID listings
and target candidates carry their actual limits. The UI additionally identifies
its smaller previews; do not substitute preview lengths for returned totals.

## Bank example: payments, mobile channel and ledger

Suppose `mobile -> payments -> ledger -> archive` is the loaded dependency
chain and the selected payments cascade has depth 1. Payments is direct;
mobile is a consumer; ledger is supporting context. Archive is **not** added
to the impact totals by the coverage probe. The panel reports that loaded
relationships continue past the downstream horizon.

If the process-support table contains only a payments mapping, mobile and
ledger have unknown process coverage. If a later read cap drops mobile's edge,
a smaller review count cannot be presented by a watch as successful remediation.
If only a process-reason list is capped, the independent compact process/system
memberships remain available for comparison.

This runnable, synthetic example exercises only the pure cascade engine:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:)"
python - <<'PY'
from datetime import datetime, timezone
from cbom.unified_cascade import unified_cascade
from shared_models.coverage import SOURCE_SCHEMA, collection_read

systems = ["mobile", "payments", "ledger", "archive"]
snapshot = {
    "systems": [{"id": sid, "name": sid} for sid in systems],
    "dependencies": [
        {"source": "mobile", "target": "payments", "type": "CALLS"},
        {"source": "payments", "target": "ledger", "type": "DEPENDS_ON"},
        {"source": "ledger", "target": "archive", "type": "CALLS"},
    ],
    "source_coverage": {"schema": SOURCE_SCHEMA, "collections": {
        "systems": collection_read(4, 20000),
        "dependencies": collection_read(3, 50000),
    }},
}
result = unified_cascade(snapshot, target="payments", kind="system",
                         max_depth=1, now=datetime(2026, 10, 18, tzinfo=timezone.utc))
assert result["impact"]["system_classification"]["review_system_count"] == 3
assert "archive" not in result["impact"]["affected_systems"]
assert result["coverage"]["known_horizon_omission"] is True
assert result["coverage"]["estate_completeness"] == "UNKNOWN"
print(result["coverage"]["status"], result["coverage"]["traversals"])
PY
```

The synthetic source metadata is illustrative; it does not validate a real
collector, authorization context or bank inventory.

## Immutable history, comparisons and watch handling

- `GET /api/v1/technology-bom/cascade/runs` returns the stored coverage summary,
  or null for legacy answers. Fetching an old run returns its original JSON.
  No historical coverage is reconstructed from today's graph.
- Diffs require versioned source metadata, compatible collection limit/unit
  profiles and traversal scope/direction/depth profiles, compatible dependency
  source families, no known input truncation/horizon omission, and no unchecked
  horizon. Existing target, relationship-policy and classification gates remain.
- When coverage is incomparable, affected-system/process and layer deltas have
  `available: false`, null before/after counts and no removal/addition claims.
  Classified and operational comparisons are also withheld. Verdicts remain
  historical facts; a verdict change alone is not proof of reduced exposure.
- Explanation-only caps do not invalidate compact membership comparison. The
  existing operational-detail comparison is separately stricter because it
  compares individual bounded declarations, not just compact system counts.
- Watches persist the incomplete answer for audit, mark attention required,
  emit no impact-removal or operational-change claim, and retain the prior
  comparable baseline. An initial incomplete run does not pin a baseline.
- A legacy baseline with unknown coverage is not silently promoted. Preserve
  its audit trail and explicitly create a new watch after owner review if a
  new comparable baseline is required; this step adds no auto-rebaseline API.

Even comparable bounded reads do not establish equal real-world discovery,
remediation, availability, or completeness. Missing links can persist in both.

## Acceptance and remaining qualification

Focused tests cover cap equality versus a real sentinel, zero budgets,
deduplicated network keys, original-input missing-reference counts, cycles,
current/potential and vendor horizons, unknown native extension, unchanged
membership under detail caps, immutable legacy history, incompatible depth and
source policies, withheld watch removals and baseline recovery. UI tests cover
prominence, unknown metadata, separate denominators and no false “unchanged.”

No migration is introduced by Step 9. Earlier migrations, including Step 8's
0101 operational dependency storage, still apply. Step 10 remains pending:
bank-specific negative authorization/tenant/backend acceptance and live backend
qualification are not established by these local tests.


### Recorded local checks

On 2026-10-18 the final scoped backend gate passed **1,687 tests** (1 skipped,
8 deselected); all **378 frontend tests** passed (42 files), as did TypeScript
checking, the production build, Python F/E9 checks, whitespace checks and this
guide's executable example. Documentation checks covered 27 Markdown files,
30 JSON blocks, 31 shell blocks and 84 API method/path references.

The expanded backend run had two pre-existing failures, reproduced against
unchanged Step 8 code; it is not claimed fully passing. See the
[roadmap qualification record](../dev/dependency-intelligence-roadmap.md#step-9--delivered-visible-bounds-and-missing-linkage)
for their exact test identities and scope. Native doubles, local SQLite and
these UI checks do not certify real Neo4j/PostgreSQL or a bank deployment.
