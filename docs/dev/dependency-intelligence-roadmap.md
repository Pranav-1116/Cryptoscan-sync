# Dependency intelligence — ten-step implementation plan

[Bank guide index](../bank-environment/README.md) ·
[Step-1 contract](../bank-environment/17-classified-system-scope.md) ·
[Step-2 contract](../bank-environment/18-shared-dependency-semantics.md) ·
[Step-3 contract](../bank-environment/19-package-artifact-deployment-identity.md) ·
[Step-4 contract](../bank-environment/20-relationship-lifecycle-and-reconciliation.md) ·
[Step-5 contract](../bank-environment/21-traversal-provenance-evidence-and-freshness.md) ·
[Step-6 contract](../bank-environment/22-business-process-impact-and-inclusion-reasons.md)

This is an incremental engineering plan for the user's ten requested changes.
**Steps 1–6 are implemented with local regression checks.** Steps 7–10
remain pending; real Neo4j/bank qualification is not implied. Pending work is not
a feature claim. Each stage needs its own implementation, regression checks,
compatibility review and a recorded delivery result before being marked done.
CI workflow configuration is outside this task.

## Status

| Step | Status | Delivery / acceptance boundary |
|---|---|---|
| 1. Separate direct exposure, consumers and context | Implemented; local checks passed | Versioned additive unified-cascade classification, disjoint memberships/counts, history/diffs/watch summaries, UI and legacy fallback |
| 2. Unify relationship semantics | Implemented; local checks passed | Versioned shared system policy in twin/memory/native Neo4j query paths; mixed-relation/min-hop/multi-owner fixtures, stored-policy/UI warnings; real Neo4j unqualified |
| 3. Join package, artifact and deployment identity | Implemented; local checks passed | Migration 0098, separate document/release digests, exact-estate explicit SBOM/deployment assertions, measured/declared identity, package/artifact cascade and evidence UI |
| 4. Edge expiry and reconciliation | Implemented; local qualification recorded below | Migration 0099, source-owned revision-checked lifecycle, atomic idempotent collection receipts, retained tombstones, as-of expiry/replay, separate uncertain reachability and UI; live PG/Neo4j remain unqualified |
| 5. Propagate provenance/evidence/freshness | Implemented; local qualification recorded below | Migration 0100, bounded traversal-evidence/1 witnesses, seed context, preserved per-edge pointers/origin/timestamp meaning, native selected-path properties and UI; no aggregate confidence or live Neo4j qualification |
| 6. Process impact over implicated systems | Implemented; local qualification recorded below | Shared process-impact/1 projection over all classified review systems; ID deduplication, per-system support reasons/roles/evidence, context/potential separation, qualified economic context and legacy comparison guards |
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

## Step 3 — delivered explicit release/deployment joins

The [step-3 contract](../bank-environment/19-package-artifact-deployment-identity.md)
records the new API, migration, bounds and operator examples. Existing package
SBOM documents can be bound to a separate immutable SHA-256 release identity and
an exact registered application/system/environment/revision declaration. The
artifact store remains the document store; SQL persists the joins and pinned
components. New supplier SBOM intake uses that same store.

Exact versioned package PURLs and release digest/ID targets seed unified
classification only through explicit deployment assertions. Unbound packages
remain unknown/insufficient rather than gaining guessed bank consumers. New
results/captures retain document hashes, release digests, sources and evidence
references; replay does not reread or retrospectively enrich from live files.
The UI labels declarations and separates measured content identity from runtime
placement. Legacy application-oriented TechBOM SBOM counts are not redefined.

New writes are role-gated, exact-tenant, idempotent and conflict rather than
silently repointing a revision. Source/container artifact writes and selected
session-tenant resolution were corrected so file and SQL ownership agree.
Tests include the real session/middleware path, foreign/platform ID denial and
SQLite migration upgrade/downgrade. Real PostgreSQL/registry/runtime placement
and full bank qualification remain unverified. Validation: 1,911 backend tests
passed (one PG-tooling skip, seven live checks deselected; CI-workflow-contract
module excluded), 352 frontend tests passed, plus typecheck, production build,
SQLite migration and documentation checks. Existing warnings remain.

## Step 4 — delivered lifecycle and conservative reconciliation

Migration 0099 adds ACTIVE/STALE/DELETED/SUPERSEDED relationship metadata to
system dependencies, SBOM bindings and deployment assertions; effective EXPIRED
is evaluated at an explicit clock. Legacy metadata remains unbounded and does not
receive a fabricated confirmation. Policy `/2` gates current propagation while
retaining nonterminal uncertainty separately from active classification.

Explicit ownership claims and state changes require writer roles, evidence and
revision CAS. Complete source-owned collections mark missing ACTIVE rows STALE;
partial/failed collection never infers absence. Bounded, monotonic and idempotent
receipts, events and updates commit atomically; collectors cannot resurrect
terminal rows. Graph deletion is now retained retirement requiring revision and
evidence. Native eligibility refresh fails closed; incomplete sync cannot prune,
and System relationship history is never absence-pruned.

Graph fingerprints/diffs include lifecycle; captured twin replay defaults to the
capture clock, with explicit alternate-clock reevaluation and named policy.
Stored answers are unchanged. The UI separates active scope from potential
uncertain systems, names unbounded eligibility and requires retirement evidence.
See [guide 20](../bank-environment/20-relationship-lifecycle-and-reconciliation.md).

Validation: **1,976 backend tests passed**, one PostgreSQL-tooling skip, seven
live checks deselected, with 114 existing warnings; CI-workflow-contract module
excluded. This includes the latest UTC-offset/SQLite normalization regression,
source bounds, two-bank/platform isolation and retained replay checks. The final
focused lifecycle/migration subset also passed **66 tests**. Frontend: **355 tests
in 38 files**, TypeScript typecheck and production build (1.24 seconds) passed.
Documentation: 22 Markdown files, 23 JSON blocks, 28 shell blocks, 83 explicit API
references and 22 positive console routes checked; executable bank examples and
new lifecycle request builders validated. New-file F/E9 lint and diff whitespace
checks passed. CI workflows were not changed.

Live PostgreSQL concurrency, real Neo4j execution, automatic collector scheduling,
source-specific TTL policy and whole-platform bank qualification remain open.

## Step 5 — delivered provenance-preserving witnesses

Implemented the additive `cryptoscan.traversal-evidence/1` contract in unified
cascade and memory/native traversal adapters. It carries real selected-edge
properties, references, assertion IDs, confidence meaning and separate observation,
confirmation and verification timestamp states. Reverse and mixed-direction walks
retain physical edge orientation. Unknown origins/references and unavailable
native paths remain explicit; no aggregate confidence or failure probability is
calculated. Asset-detection confidence no longer verifies a relationship.

SQL graph/twin projection retains declared/imported/discovered origins. Migration
0100 adds optional dependency evidence references and confidence meaning without
fictional legacy backfill. Software seeds retain document/release/deployment
assertions; other adapters carry available source records or explicit unverified
legacy context. Native membership is independent of bounded witness queries;
vendor chains query the requested neighborhood rather than export a replacement
whole graph. Corrected duplicate SET tokens in native node-write templates while
retaining managed-revision guards.

At most 500 witnesses per group and 50 references per edge are listed, with
explicit missing/truncated coverage that never drives exposure counts. Stored
answers retain their explanation; old answers are not reconstructed from current
relationships. UI and API preserve declarations versus runtime observations.
Local release validation: 1,996 backend tests passed (1 skipped, 7 deselected),
358 frontend tests passed, typecheck/build/docs/lint passed. CI workflows unchanged.
These are payload bounds, not dense-graph load certification. Process closure,
exact target matching, operational modes and bank-wide negative qualification
were the remaining steps at this delivery; step 6 is delivered below. Details and a runnable example are in
[bank guide 21](../bank-environment/21-traversal-provenance-evidence-and-freshness.md).

## Step 6 — delivered process projection and inclusion reasons

`cryptoscan.business-process-impact/1` projects recorded support across all
classified review systems, not just direct seeds. Processes deduplicate by ID;
every retained reason names its supporting system, scope, role, mapping record,
per-edge evidence/freshness and system-explanation reference. Context-only and
potential-only processes are separate from active modeled exposure. Supplied
uncertain support metadata cannot become current exposure; terminal mappings
are excluded. This is not a new support-map lifecycle-write/reconciliation API.

SQL snapshot/graph builders retain actual support IDs/roles. Both graph adapters
use the shared reducer; native reads selected support properties rather than
aggregating distinct numeric values. Equal-value distinct processes remain
separate; missing/conflicting metrics and unmapped exposed systems are explicit.
Economic context excludes context-only/potential-only processes and never claims
predicted loss, unique customer counts or validated currency compatibility.

Detailed process/reason limits are independent of counts. Snapshot process/link
source caps are exposed. Stored new runs retain the projection; old answers stay
unchanged. Mixed-version process diffs are explicitly noncomparable. UI presents
scope/reasons/gaps and qualifies economic values. Graph impact freezes one clock
without mutating later reads; existing forward-only compliance semantics remain.

Local validation: 2,017 backend tests passed (1 skipped, 7 deselected), 361
frontend tests passed across 40 files; typecheck/build/docs/lint passed.
No new migration: existing migration 0100 remains a deployment prerequisite.
Native stored-projection freshness/reconciliation, real Neo4j execution, live PG
concurrency, broad load and whole-bank negative qualification remain open.
See [bank guide 22](../bank-environment/22-business-process-impact-and-inclusion-reasons.md).

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
