# 22 — Business-process impact and inclusion reasons

**Implemented step 6, 18 October 2026.** A process is included because of recorded
support mappings on implicated systems—not because CryproScan has observed the
process fail. This extends [classified system scope](17-classified-system-scope.md)
and [per-edge explanations](21-traversal-provenance-evidence-and-freshness.md).
Exact target matching, operational dependency modes, broader coverage UX and
whole-bank negative qualification remain steps 7–10.

## 1. The gap that is closed

Previously, unified cascade generally projected processes from directly matched
systems only. A signing-service change could reach a mobile channel through
registered dependencies while omitting the mobile channel's business process.
The memory business-impact path mainly examined forward support context. The
native financial aggregate also used `DISTINCT` on numeric amounts, which could
collapse two different processes with equal recorded revenue.

The shared `cryptoscan.business-process-impact/1` projection now resolves process
support across **all classified review systems**, deduplicating by process ID.
It is used by unified cascade and both graph adapters. Native process projection
reads actual selected system→process relationship properties; it does not export
the entire graph or invent support edges from system names.

This does not add missing support declarations, discover unregistered processes,
or establish whether a service actually fails after a cryptographic change.

## 2. Scope and count rules

| Supporting system's scope | Process interpretation |
|---|---|
| Direct exposure | Recorded support from a directly selected system |
| Dependent consumers | Recorded support from a reverse-reachable registered consumer |
| Supporting context | Forward-only dependency/change context; not automatically exposed |
| Potential | Additional uncertain system reachability; not active exposure |

A process can have several reasons across these scopes. Its ID is counted once:

- **Exposure:** at least one current support mapping from a direct system or
  dependent consumer.
- **Context-only:** current support exists in the review scope, but none from an
  exposed system.
- **Review:** exposure plus context-only processes.
- **Potential-only:** only uncertain reasons are available, with no current
  review support mapping. This is separate from review/exposure counts.

A process can retain potential reasons while also having current exposure; it
is not counted again as potential-only. Cycles and multiple supporting systems
must not inflate its process count. Equal names do not identify the same process;
equal numeric revenue values do not identify the same process either.

The projection conservatively interprets lifecycle metadata when supplied on a
support assertion. Current mappings can contribute to review; stale, expired or
unknown nonterminal mappings can contribute only potential reasons; terminal
mappings cannot extend exposure. **This step does not add a lifecycle-write or
reconciliation API for `SystemBusinessProcess`.** Its existing SQL schema is
unchanged; ordinary persisted support mappings remain declarations without a new
expiry guarantee.

## 3. Why each process is included

`impact.process_impact.processes[]` carries:

- The process ID, display name and a conflicting-name indicator.
- All represented system-scope classes, with explicit exposure/context-only/
  potential-only flags.
- A bounded list of inclusion reasons, plus the full loaded reason count.
- Each reason's supporting system ID, system scope and current/potential status.
- The actual mapping record ID and declared `role`, where available.
- A `support_link` containing source/provenance, references and timestamp meaning
  using the step-5 edge-evidence contract.
- A `system_explanation` reference pointing to that system's seed/path explanation.
  Its availability flag says that an explanation entry is present; it does not
  independently verify a complete runtime chain.

The process ID is never silently reused as a missing support assertion ID. Older
compact snapshots without original join metadata retain an unattributed mapping
and missing references. Missing witness payloads do not remove otherwise
recorded process associations from counts.

Roles such as `PRIMARY`, `CHANNEL`, `FRONTEND` or `SUPPORT` remain producer-supplied
labels. They do not establish all-of/any-of availability rules, hard dependencies,
failover guarantees or buffering behavior. No edge confidence is multiplied into
an aggregate process failure probability.

SQL→snapshot and SQL→graph projection now retain real mapping IDs and roles.
JSON graph round trips preserve them. Graph impact also exposes
`process_traversal_evidence` for the corresponding direct/reverse/forward system
reasons; its legacy `traversal_evidence` field remains the forward envelope.

## 4. Business values are context, not predicted loss

The projection carries recorded process `revenue_daily` and `customer_count`.
It sums **distinct exposed process IDs only**. Context-only and potential-only
processes do not inflate exposure business-context totals.

Two processes with revenue 100 each contribute 200, even if they share a display
name. One process supported by two systems contributes its recorded revenue once.
Customer populations can overlap across different processes; their arithmetic
sum is **not a count of unique affected people**.

Missing, invalid, negative, non-finite or conflicting metrics are unknown, not
silently zero. Each metric reports its known sum and missing/conflicting process
count. `complete_sum` is null if metrics are incomplete, an exposed system lacks
a current support mapping, or aggregate arithmetic overflows. An overflow also
makes `known_sum` null rather than emitting non-JSON infinity.

“Complete” is only relative to loaded process metrics and recorded mappings. It
is not evidence that the inventory is complete. No currency, currency conversion,
accounting-unit compatibility or business-loss scenario is verified. The UI
labels these numbers declared business context, not predicted loss.

Graph impact retains `total_revenue_at_risk` and `total_customers_at_risk` as
legacy aliases for exposed-process **known context sums**, with an explicit
`economic_totals_meaning` qualifier. New consumers should use the structured
`process_impact.economic_context`, not interpret these aliases as incident losses.
Graph simulation/explanation responses carry the process explanation as well;
their older simulation counters do not acquire a failure model through this step.

## 5. Coverage, bounds and historical compatibility

Missing process support is unknown, not zero impact. Coverage reports include:

- Implicated system count and systems without usable recorded support links.
- Unresolved/invalid support targets (including targets outside loaded registry
  caps) and excluded terminal links.
- Source truncation flags for newly captured SQL twin process/link collections.
  Missing source coverage on a legacy or graph-only projection stays unknown.
- Full loaded process count versus returned detailed explanations.

At most **500 detailed processes**, **200 reasons per process**, and **500 missing
system IDs** are listed. The UI previews twenty processes and ten reasons per
process and labels those display limits. Counts and business-context sums are
computed before these explanation limits. The compact review ID/name list remains
available in `affected_processes`/`review_processes`; these are compatibility
membership lists, not bounded reason payloads or confirmed failure counts.

Unified cascade's `layers.process.processes` and `impact.affected_processes` now
represent the full **loaded review-process union**, not the previous seed-only
subset. Context-only processes are identifiable in the versioned projection.
A larger process list can therefore result from the scope correction alone.

New saved answers contain their process projection. Older answers are not
recomputed from today's support mappings. Run diffs include `process_comparison`:
comparability requires the current process schema, system classification and
matching system relationship policy. Raw compatibility deltas remain available,
but the UI refuses to present mixed-version process counts as comparable business
changes. This is not a complete reason-level change-analysis engine.

A graph business-impact request uses one fixed clock for its forward walk,
reverse walk, mapping eligibility and process projection without changing the
clock of later reads on the graph instance. Historical unified replay continues
to use the supplied capture/request clock.

## 6. Runnable bank example

These IDs and reference strings are fictional fixture values, not objects to paste
into a bank estate. Run with the repository service/shared packages on `PYTHONPATH`:

```python
from datetime import datetime, timezone
from cbom.unified_cascade import unified_cascade

now = datetime(2026, 10, 18, tzinfo=timezone.utc)
estate = {
    "systems": [{"id": s, "name": s} for s in ("mobile", "payments", "ledger", "backup")],
    "dependencies": [
        {"source": "mobile", "target": "payments", "type": "CALLS"},
        {"source": "payments", "target": "ledger", "type": "IMPORTS"},
        {"source": "backup", "target": "payments", "type": "CALLS", "lifecycle_state": "STALE"},
    ],
    "business_processes": {
        "payments": [{"id": "authorize", "name": "Payment authorization",
            "revenue_daily": 100, "customer_count": 10,
            "relationship_record_id": "map-pay", "role": "PRIMARY", "provenance": "DECLARED"}],
        "mobile": [
            {"id": "authorize", "name": "Payment authorization", "revenue_daily": 100, "customer_count": 10,
             "relationship_record_id": "map-mobile", "role": "CHANNEL", "provenance": "DECLARED"},
            {"id": "mobile-service", "name": "Mobile banking", "revenue_daily": 100, "customer_count": 10},
        ],
        "ledger": [{"id": "reconciliation", "name": "Reconciliation", "revenue_daily": 9000}],
        "backup": [{"id": "contingency", "name": "Contingency processing", "revenue_daily": 8000}],
    },
}
answer = unified_cascade(estate, target="payments", kind="system", now=now)
projection = answer["impact"]["process_impact"]
assert projection["counts"] == {"review": 3, "exposure": 2, "context_only": 1, "potential_only": 1}
authorize = next(p for p in projection["processes"] if p["id"] == "authorize")
assert authorize["reason_count"] == 2
assert {r["system_scope"] for r in authorize["reasons"]} == {"direct_exposure", "dependent_consumers"}
assert projection["economic_context"]["revenue_daily"]["known_sum"] == 200
assert projection["economic_context"]["customer_count"]["known_sum"] == 20
assert next(p for p in projection["processes"] if p["id"] == "reconciliation")["context_only"]
assert next(p for p in projection["processes"] if p["id"] == "contingency")["potential_only"]
assert {p["id"] for p in answer["impact"]["affected_processes"]} == {"authorize", "mobile-service", "reconciliation"}
```

The example's 200 is a numeric sum of declared context for two process IDs. It
is not a currency-validated loss forecast. Its twenty customer-count units are
not demonstrated unique people. The stale backup path does not become active
process exposure.

## 7. Delivery and remaining qualification

No new database migration is required for step 6. It reuses existing process,
role and support-map fields plus additive JSON response/snapshot fields. An
existing installation still needs the previously delivered migration **0100**.

Regression coverage includes consumer/context closure, multiple support reasons,
equal-name/equal-value distinct IDs, shared assets, metadata round trips, relation
policy negatives, stale/terminal support assertions, unknown/conflicting metrics,
overflow, output bounds, one-clock evaluation, SQL role/ID projection, source
caps, retained historical answers, mixed-version diff guards and UI disclosures.

Final local checks: **2,017 backend tests passed**, 1 skipped and 7 deselected;
**361 frontend tests passed across 40 files**. TypeScript checking, production
build, changed-Python F/E9 lint, documentation link/JSON/shell/API-route checks,
and runnable bank examples passed. CI workflows remain unchanged. These results
are not a live bank-estate acceptance certificate.

The Bolt double does not parse or execute Cypher. Native process answers reflect
the stored graph projection; this step does not certify automatic SQL→native
support-map reconciliation or continuous freshness. Real Neo4j execution,
PostgreSQL concurrency, dense-estate load, independent pointer verification and
bank-wide role/tenant negatives remain unqualified. The broader operational
failure/failover model is still pending. See the
[implementation roadmap](../dev/dependency-intelligence-roadmap.md).
