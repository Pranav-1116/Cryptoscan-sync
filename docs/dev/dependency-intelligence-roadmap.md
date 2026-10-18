# Dependency intelligence — ten-step implementation plan

[Bank guide index](../bank-environment/README.md) ·
[Step-1 contract](../bank-environment/17-classified-system-scope.md) ·
[Step-2 contract](../bank-environment/18-shared-dependency-semantics.md)

This is an incremental engineering plan for the user's ten requested changes.
**Steps 1 and 2 are implemented with local regression checks.** Steps 3–10
remain pending; real Neo4j/bank qualification is not implied. Pending work is not
a feature claim. Each stage needs its own implementation, regression checks,
compatibility review and a recorded delivery result before being marked done.
CI workflow configuration is outside this task.

## Status

| Step | Status | Delivery / acceptance boundary |
|---|---|---|
| 1. Separate direct exposure, consumers and context | Implemented; local checks passed | Versioned additive unified-cascade classification, disjoint memberships/counts, history/diffs/watch summaries, UI and legacy fallback |
| 2. Unify relationship semantics | Implemented; local checks passed | Versioned shared system policy in twin/memory/native Neo4j query paths; mixed-relation/min-hop/multi-owner fixtures, stored-policy/UI warnings; real Neo4j unqualified |
| 3. Join package, artifact and deployment identity | Pending | Tenant-scoped immutable content identity and explicit substantiated deployment bindings, not mutable path/tag inference |
| 4. Edge expiry and reconciliation | Pending | Freshness lifecycle, explicit stale/deleted/tombstoned states and idempotent reconciliation without silent evidence destruction |
| 5. Propagate provenance/evidence/freshness | Pending | Versioned path-level explanations preserving sources, evidence references, observation times and confidence meaning |
| 6. Process impact over implicated systems | Pending | Process closure over defined system scopes, deduplication and explicit inclusion reasons, not invented revenue loss |
| 7. Exact target identities | Pending | Exact certificate/package/vendor resolution, explicit ambiguity and opt-in broad search rather than silent first match |
| 8. Operational dependency modes | Pending | Distinct hard/optional/failover/asynchronous-buffering semantics with conditional outcomes and unknowns, not probabilistic failure claims |
| 9. Prominent coverage/truncation | Pending | Per-collection and per-walk bounds, missing-link coverage and UI warnings without treating absence as clean |
| 10. Bank-negative and backend qualification | Pending | Role/tenant/history/replay/write denial tests, backend parity and bank-specific acceptance evidence; mocks alone do not qualify deployment |

## Step 1 — delivered scope and compatibility

`impact.system_classification` uses `cryptoscan.cascade-system-scope/1` with three
disjoint buckets and exposure/review unions. Direct seeds win over reverse
consumers, then supporting context. Raw directional walks are preserved.

Legacy affected fields retain their full review meaning. Historical results are
not rewritten; missing classification remains unknown. Read models emit bounded
count-only summaries; full memberships stay with the persisted run. New run diffs
can report a category move even when the review union stays constant.

Current watches return category counts but still alert on their existing
aggregate membership changes, not category-only moves. Step 1 did not include
a new relation policy (subsequently delivered in step 2), scheduler, exact
matching, process closure, persistence migration or availability simulator.

Validation: 103 selected backend tests, 349 frontend tests (37 files), TypeScript
typecheck and frontend production build passed. Details and limitations are in
[the step-1 contract](../bank-environment/17-classified-system-scope.md).

## Step 2 — delivered system relationship policy

`cryptoscan.system-dependency-policy/1` defines consumer -> provider direction.
CALLS, IMPORTS, IMPORTS_CRYPTO and DEPENDS_ON propagate between known systems;
context/inventory/unknown labels do not. Missing/null/blank legacy declarations
retain CALLS compatibility. New transport labels are kept separate from semantic
labels, with a bounded decoder for old Neo4j protocol-overloaded rows.

Memory and native Neo4j forward/reverse, shortest-system-path, cycle and
vendor-system-prefix paths use this policy, as does unified system propagation.
Forward/reverse asset starts include all owners, minimum depths are deduplicated,
seed cycles are excluded, and walks are bounded. Domain-specific supplier walks
remain separate. This does not join missing inventories or reconcile old edges.

New runs persist policy metadata; old results remain immutable/unknown-policy.
Classification diffs require matching known policy versions. UI and watch
comparison metadata prevent unexplained count changes from being sold as
remediation. Existing watch aggregate alert behavior is preserved.

The [step-2 contract](../bank-environment/18-shared-dependency-semantics.md)
records storage compatibility, scope and reproducible checks. Local validation:
1,044 backend tests, 350 frontend tests (37 files), the final six panel tests,
typecheck, production build and documentation checks passed. Regression tests
cover mixed labels, unknowns, chains/diamonds/cycles, depth, multiple asset owners,
endpoint namespaces, legacy storage, API persistence/replay/diff and UI warnings.
The tagged-query Bolt double does not execute Cypher; real Neo4j qualification,
existing-database migration/reconciliation and bank acceptance remain pending.

## Step 3 — next implementation boundary

Join standalone package SBOM components to immutable artifact content/digests
and substantiated deployed application/system identity. Reuse existing SBOM,
artifact and application models where possible. A mutable filename, image tag,
package name or source-system guess must not become deployment proof. Preserve
supplier-declared versus observed bindings, enforce tenant scope, test missing
and conflicting identities, and avoid inventing consumers for an unbound SBOM.

## Later stages — design constraints

### Steps 3–4: identity and lifecycle first

Bind software rows to actual immutable artifact bytes/digests and explicit
application/deployment identity. Keep supplier assertions and bank-observed
provenance distinct. Scope all lookup/write/read paths by the authorized tenant.
A source path, tag, package name or timestamp alone is not immutable release
identity.

Introduce stale/expired/deleted edge handling without making an expired link
look like proof of no relationship. Reconciliation should be idempotent, auditable
and source-aware, including partial/failed collection safeguards. Reuse repository
migration conventions; do not create hidden alternate data stores.

### Steps 5–6: explanations and process projection

Keep all justified paths or an explicitly bounded explanation set with reported
truncation. Preserve why a system is directly linked or reached as a consumer or
context, including overlaps that disjoint presentation prioritizes.

Resolve processes from all intended implicated scopes, carry supporting-system
and path/category reasons, and deduplicate process identity. Distinguish consumer
business exposure from supporting change context; monetary metadata is not a
measured loss forecast.

### Steps 7–8: precision without false certainty

Exact identifiers must be preferred and ambiguity rejected/reported before broad
matching. Preserve ecosystem, version, product and release context. An exact
certificate target must not later become an ambiguous subject-only endpoint join
without an explicit confidence/coverage signal.

Operational modes need bank evidence. A failover edge is not proof failover will
work; asynchronous buffering needs capacity/freshness assumptions. Missing
operational metadata must stay unknown, not default to guaranteed failure or
safety.

### Steps 9–10: visible bounds and negative qualification

Expose collection and traversal bounds separately, label unknown/unlinked/stale
objects and keep scope denominators. Verify that summaries/export/diffs do not
silently remove the warnings.

Exercise unauthorized, wrong-tenant, revoked, ambiguous, foreign-ID and historic
record cases across reads, writes, adoption, deployment binding, history, replay
and watches. Compare supported backends with the same policy and fixture, then
qualify real bank runtime integrations separately. No passing local suite alone
constitutes a customer acceptance or production certification.
