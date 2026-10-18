# Dependency intelligence — ten-step implementation plan

[Bank guide index](../bank-environment/README.md) ·
[Delivered step-1 contract](../bank-environment/17-classified-system-scope.md)

This is an incremental engineering plan for the user's ten requested changes.
**Only step 1 is implemented in this iteration.** Pending work below is not a
feature claim. Each stage needs its own implementation, regression checks,
compatibility review and a recorded delivery result before being marked done.
CI workflow configuration is outside this task.

## Status

| Step | Status | Delivery / acceptance boundary |
|---|---|---|
| 1. Separate direct exposure, consumers and context | Implemented; local checks passed | Versioned additive unified-cascade classification, disjoint memberships/counts, history/diffs/watch summaries, UI and legacy fallback |
| 2. Unify relationship semantics | Next; not implemented | Shared directional/relation policy across twin, memory and Neo4j, with explicit unknown/non-propagating relationships and parity fixtures |
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
aggregate membership changes, not category-only moves. No new scheduler,
relation policy, exact matching, process closure, persistence migration or
availability simulator is included.

Validation: 103 selected backend tests, 349 frontend tests (37 files), TypeScript
typecheck and frontend production build passed. Details and limitations are in
[the step-1 contract](../bank-environment/17-classified-system-scope.md).

## Step 2 — next implementation boundary

Before changing traversal, define one canonical meaning for a directed consumer
-> provider edge and classify relationship types explicitly. CALLS, IMPORTS,
imports-crypto, containment, ownership and inventory projection must not silently
become identical runtime dependencies.

Required work:

1. Inventory producers/consumers of relationship labels and namespace differences.
2. Specify a versioned shared relation policy, including aliases, unsupported
   labels, non-propagating context and reverse traversal behavior.
3. Apply it consistently to graph construction, twin propagation, memory queries
   and Neo4j queries; do not hide a policy change behind a backend fallback.
4. Preserve legacy output compatibility or declare explicit policy/version
   differences; record policy metadata with stored answers.
5. Test chains, diamonds, cycles, mixed/non-CALLS labels, unknown relations,
   multi-asset owners and isolated/no-link cases against identical fixture data.
6. Distinguish deterministic unit/double tests from real Neo4j qualification and
   leave deployment qualification pending where the real backend is unavailable.

The direct/consumer/context classification in step 1 consumes the current
traversal outputs. It does not itself resolve their existing semantic differences.

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
