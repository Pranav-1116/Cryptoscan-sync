# 18 — Implemented step 2: shared system-dependency semantics

[Guide index](README.md) · [Step 1](17-classified-system-scope.md) ·
[Engineering plan](../dev/dependency-intelligence-roadmap.md)

> Subsequent step 4 adds lifecycle eligibility in policy `/2`; this guide records
> the original step-2 `/1` relation contract. See [lifecycle and reconciliation](20-relationship-lifecycle-and-reconciliation.md)
> for current expiry, history-clock and source-owned collection behavior.

## 1. Delivery boundary

The system-dependency portions of memory queries, Neo4j adapter queries and
unified cascade now use one versioned policy:
**`cryptoscan.system-dependency-policy/1`**. New answers record this as
`relationship_policy`; historical answers are not rewritten.

This standardizes the meaning of **the same supplied system relationships**. It
does not make distinct collectors assemble identical estates, reconcile stale
stored relationships, simulate availability or join a standalone package SBOM
into deployed application identity. Those are separate pending stages.

Local regression and adapter-double checks passed. Real Neo4j execution and bank
deployment parity have **not** been qualified in this environment.

## 2. Direction and relation vocabulary

An arrow means **consumer -> provider**:

```text
mobile -> gateway -> payments -> signing
```

A forward walk from payments returns signing as supporting dependency context.
A reverse walk returns gateway and mobile as modeled dependent consumers. It
does not assert those consumers will stop working.

| Relation | System-to-system propagation |
|---|---|
| `CALLS` | Yes: modeled invocation dependency |
| `IMPORTS` | Yes: modeled static import dependency, not proof of execution |
| `IMPORTS_CRYPTO` | Yes: modeled crypto import dependency |
| `DEPENDS_ON` | Yes: explicitly declared generic dependency |
| `CONTAINS`, `USES`, `SUPPORTS`, `OWNED_BY`, `MUST_COMPLY_WITH` | No: membership, business or inventory linkage |
| `SECURED_BY`, `DEPLOYED_ON`, `DEPENDS_ON_VENDOR`, `CONNECTS_TO`, `RUNS`, `PROTECTED_BY`, `RELATED` | No: domain/context linkage, not an interchangeable system dependency |
| Any unrecognized explicit label, including `HTTP`, `OPTIONAL`, `FAILOVER` | No: unsupported meaning is not silently promoted to dependency |

Labels are trimmed, uppercased, and spaces/hyphens converted to underscores;
`imports-crypto` and `depends on` therefore normalize to known dependency labels.
An absent, null or blank relation defaults to `CALLS` for compatibility with
historical nullable system declarations. This exception is explicit in metadata;
it is **not** the rule for arbitrary unknown labels. Dependency edge dictionaries
read `relation`, then `type`, then `label` when the earlier value is absent/null.
New transport/protocol values do not become semantic relation names.

No edge in this allowlist is classified as guaranteed operationally hard. Optional,
failover and buffering behavior need step 8's explicit operational model. An
unsupported label being excluded is not evidence the corresponding dependency
cannot exist: it needs review and supported modeling.

## 3. System walks, depth and multiple owners

- Only known System nodes can bridge a system-dependency walk. An asset,
  process, owner, supplier or missing system node cannot be used as an
  intermediate shortcut, even if an edge is labeled `CALLS`.
- Raw system IDs and dependency endpoints prefixed with `system:` are accepted;
  other namespaces are not stripped into system identity.
- Forward/reverse asset-start walks seed **all** known owning systems via `USES`,
  not the first owner. Ownership is a seed-resolution operation, not propagation.
- Results exclude the complete seed set, deduplicate systems and report minimum
  hops from any seed, sorted by hops, name and ID. `owning_systems` records seeds.
  `nodes_visited` counts distinct seeds plus distinct returned systems, not rows
  or duplicate paths.
- Graph forward/reverse walks clamp depth to 1–12; unified cascade validates a
  requested depth of 1–12. Shortest system paths are bounded to 12 hops too.
- Cycles use the same system relation policy. A cycle can put one system in both
  raw directions; step 1's precedence still makes classified buckets disjoint.
- Vendor-path queries filter their system dependency prefix with this policy,
  then permit a terminal `DEPENDS_ON_VENDOR` domain link. Their maximum is 12
  system hops plus that final link. Declared supplier/sub-tier traversal remains
  a separate VBOM operation, not a system-only BFS.

Asset-start multi-owner support here applies to forward/reverse walks. Shortest
path is primarily a system-to-system API; generalized all-owner asset-to-asset
shortest path resolution is not delivered by this step.

### Mixed bank fixture

```text
mobile --CALLS--> gateway --DEPENDS_ON--> payments
payments --IMPORTS_CRYPTO--> signing
payments --IMPORTS--> ledger
admin --CONTAINS--> payments
unclassified --CUSTOM--> payments
```

For a payments target at depth two:

- Direct: payments, count 1.
- Consumers: gateway (one hop), mobile (two hops), count 2.
- Supporting context: signing and ledger, count 2.
- Modeled exposure: 3; full review: 5.
- Admin and unclassified do not enter propagation from those labels alone.

A diamond returns each system once at its minimum depth. Adding a dependency
cycle does not reintroduce the seed as its own descendant. Parallel `CALLS` and
`CONTAINS` labels between the same systems retain their separate meanings.

## 4. Neo4j storage and legacy compatibility

Existing storage uses physical Neo4j `:CALLS` relationships for registered system
edges. New writes preserve the normalized semantic `relation` property separately
from `protocol`; distinct semantic labels are distinct relationship identities.
Export reads semantic labels rather than flattening every edge back to CALLS.
The physical relationship type alone is therefore **not** a complete dependency
predicate.

For rows without an explicit semantic property, the old overloaded `protocol`
field is decoded using a bounded compatibility rule:

- The four recognized dependency labels remain propagating.
- Legacy transport labels `HTTP`, `HTTPS`, `TCP`, `TLS`, `GRPC`, `ISTIO`, `MESH`
  mean CALLS when stored on an old physical CALLS relationship.
- Missing/blank legacy protocol defaults to CALLS.
- Known context and arbitrary custom labels do not propagate.
- An explicit **new** `relation=HTTP` is still unsupported/non-propagating;
  `protocol=HTTP` does not override an explicit semantic relation.

Cypher receives bound allowlist parameters, requires System-only paths, excludes
seed cycles, and groups forward/reverse results using `min(length(path))`. The
shortest-path and vendor-prefix queries apply the same predicate. There is no
hidden export-to-memory fallback for these native queries.

**No destructive migration or edge reconciliation was introduced.** A database
previously synchronized under the old writer can retain legacy relationships
alongside new semantic rows. Changing/removing an input relation does not promise
that old edges have disappeared. Known-clean equivalent input fixtures are the
local parity boundary; existing installations need a reviewed migration and
[step 4's lifecycle/reconciliation](20-relationship-lifecycle-and-reconciliation.md)
and reviewed legacy ownership before that equivalence can be assumed. Do not
blindly delete production graph evidence to force matching counts.

## 5. API, history, replay and UI

New unified answers include metadata shaped as follows (abridged):

```json
{
  "relationship_policy": {
    "version": "cryptoscan.system-dependency-policy/1",
    "direction": "consumer_to_provider",
    "propagating_relations": ["CALLS", "DEPENDS_ON", "IMPORTS", "IMPORTS_CRYPTO"],
    "unknown_relations": "non_propagating",
    "unspecified_relation": "CALLS",
    "max_system_hops": 12
  }
}
```

- `POST /api/v1/technology-bom/cascade` persists the versioned policy with the
  full result, including NOT_FOUND results.
- `GET /api/v1/technology-bom/cascade/runs` and watch execution return stored or
  current policy metadata alongside the classified counts.
- `GET /api/v1/technology-bom/cascade/runs/{run_id}` retrieves the original result,
  not a recalculated answer under today's policy.
- `GET /api/v1/technology-bom/cascade/runs/{run_id}/diff` adds `policy_comparison`.
  Category comparison is unavailable if either policy is unknown or versions
  differ, even when both runs have step-1 classification. Legacy review
  membership deltas remain available but are not proof of remediation.
- Replaying a captured twin uses the **current engine and policy** over that
  captured input; it records the new policy and replay provenance without
  modifying the captured snapshot. It does not reproduce an old engine binary.
- `GET /api/v1/graph/edges` includes normalized semantics, a `propagates` flag and
  policy version per registered edge. The flag describes label eligibility, not
  evidence freshness or guaranteed runtime execution.
- The Cross-BOM panel shows the version/allowlist, warns when a stored policy is
  absent, and warns against interpreting mixed-policy diffs as remediation.

Watches retain their existing aggregate-membership alert behavior, with policy
comparability metadata added when comparing an available prior run. This is not
a new alert taxonomy, scheduler or automatic old-run backfill.

A count can decrease because containment/unknown links stopped bridging systems;
it can increase because IMPORTS dependencies are now consistently traversed. Such
policy changes are **not demonstrated risk reduction or a newly measured outage**.
Legacy `affected_systems`/count still mean full review union, not exposure only.

## 6. Implementation and reproducible checks

Primary sources:

- [Shared policy](../../shared/shared_models/shared_models/dependency_semantics.py)
- [Memory engine](../../services/graph_engine/graph_engine/core/engine.py) and
  [Neo4j adapter](../../services/graph_engine/graph_engine/core/store.py)
- [Real query text](../../services/graph_engine/graph_engine/queries/dependents.py)
  and [storage writes](../../services/graph_engine/graph_engine/builders/cypher_writes.py)
- [Unified cascade](../../services/cbom/cbom/unified_cascade.py)
- [Parity fixtures and query contracts](../../services/graph_engine/tests/test_dependency_policy_parity.py)
- [Policy unit tests](../../shared/shared_models/tests/test_dependency_semantics.py)
- [API regression tests](../../services/api/tests/unit/test_cascade_api.py)

Focused local checks, after installing the repository's Python dependencies:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:)"
python -m pytest -q -p no:xdist \
  shared/shared_models/tests/test_dependency_semantics.py \
  services/graph_engine/tests \
  services/cbom/tests/test_unified_cascade.py \
  services/api/tests/unit/test_cascade_api.py
(cd frontend && npm run typecheck && npm test && npm run build)
```

Recorded local validation for this delivery:

- **1,044 backend tests passed** across shared-model, graph-engine and CBOM
  suites plus the selected graph/cascade API regression suites.
- **350 frontend tests passed in 37 files**; the final six-test cascade panel
  suite was also re-run after its historical-policy assertion was added.
- TypeScript typecheck and production frontend build passed.
- Documentation links/anchors, JSON/shell syntax and API route references passed;
  the earlier bank example fixture and request-model examples also passed.
- Existing backend deprecation/field-shadow warnings and frontend React `act`
  warnings remain; warning cleanup is not claimed. CI workflows were not changed.

The Bolt double dispatches tagged queries to Python handlers; it does **not**
execute or parse Cypher. Tests also inspect the actual query text and parameters,
which catches omitted predicates but does not establish real syntax/planner,
tenant isolation, performance or deployment correctness. This environment has no
running Neo4j, Docker or Java available. Real-backend/bank qualification remains
step 10, not a passing-mock certification.

## 7. Subsequent delivery and remaining work

[Step 3](19-package-artifact-deployment-identity.md) subsequently delivered explicit
package/release/deployment joins; its assertions do not prove current runtime
placement. At the time of the step-2 delivery, the backlog below was pending;
step 4 now supplies [stale/deleted lifecycle and reconciliation](20-relationship-lifecycle-and-reconciliation.md);
[step 5 supplies bounded per-edge provenance/freshness explanations](21-traversal-provenance-evidence-and-freshness.md).
[Step 6 supplies process closure and inclusion reasons](22-business-process-impact-and-inclusion-reasons.md).
Steps 7–10 remain pending:
exact/ambiguous target resolution, operational dependency modes, prominent
coverage/truncation and bank-negative deployment qualification. The same policy
on different incomplete or stale inventories can still return different counts.
