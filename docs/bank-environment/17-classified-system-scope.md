# 17 — Implemented step 1: classified system scope

[Guide index](README.md) · [Ten-step implementation plan](../dev/dependency-intelligence-roadmap.md)

Subsequent delivery: [step 2](18-shared-dependency-semantics.md) now controls
which relationships feed these buckets. The step-1 validation below remains a
historical result, not a claim that all later stages are still unimplemented.

## 1. What changed

New unified-cascade answers now separate three **disjoint system buckets**:

| Bucket | Meaning |
|---|---|
| `direct_exposure` | Seed systems linked to the selected target through that target's current evidence/linkage path |
| `dependent_consumers` | Other systems reached by reverse dependency traversal |
| `supporting_context` | Forward-only dependencies, excluding direct seeds and dependent consumers |

These are modeled relationships, not confirmed failures or proof of runtime
execution. “Direct” means a seed from current linkage, not necessarily a directly
measured production call. Target matching, relationship semantics, freshness and
coverage limitations remain unless separately changed in a later step.

The API's full result stores the classification in
`impact.system_classification`, with schema
`cryptoscan.cascade-system-scope/1`.

## 2. Membership, overlap and counts

Precedence is deterministic:

```text
direct exposure wins over dependent consumers
 dependent consumers win over supporting context

modeled exposure = direct exposure UNION dependent consumers
review scope     = modeled exposure UNION supporting context
```

A system that participates in a cycle can be reachable both forwards and
backwards. It counts once, under the precedence above. Raw directional depth
maps remain unchanged in `layers.system`, so overlap is not deleted from the
underlying explanation.

Each bucket has sorted `systems` and a deduplicated `count`. The classification
also returns `exposure_systems`, `exposure_system_count`, `review_systems` and
`review_system_count`.

### Bank example

```text
Mobile Banking -> Payments API -> Ledger
```

For the system target Payments API, partial classification is:

```json
{
  "schema": "cryptoscan.cascade-system-scope/1",
  "direct_exposure": {"systems": ["payments"], "count": 1},
  "dependent_consumers": {"systems": ["mobile"], "count": 1},
  "supporting_context": {"systems": ["ledger"], "count": 1},
  "exposure_systems": ["mobile", "payments"],
  "exposure_system_count": 2,
  "review_systems": ["ledger", "mobile", "payments"],
  "review_system_count": 3
}
```

These IDs are illustrative. Ledger is included for supporting/change context,
not automatically labeled a consumer affected by Payments API failing.

## 3. API compatibility and history

- `POST /api/v1/technology-bom/cascade` includes full memberships/counts.
- The persisted run keeps that classification with its original result.
- `GET /api/v1/technology-bom/cascade/runs` returns count-only classification
  summaries, avoiding repetition of large membership lists across history rows.
- `GET /api/v1/technology-bom/cascade/runs/{run_id}` returns the stored result,
  including full classification when the original run had it.
- `GET /api/v1/technology-bom/cascade/runs/{run_id}/diff` adds category deltas
  when both stored runs use the current classification schema. It can show a
  role change even when the full review union/count did not change.
- Watch execution returns current count-only scope summaries. Existing watch
  aggregate-membership alert behavior is retained; this step does not introduce
  category-only watch alerts or a scheduler.

Legacy `impact.affected_systems` and `affected_system_count` remain the full
review union for compatibility. **They are not redefined as consumer-exposure
counts.** New clients should use the explicitly named classification.

Older persisted answers are not rewritten, inferred, replayed against current
data or filled with invented zero buckets. Their history classification is
`null`; mixed old/new diffs return `system_classification.available=false`.
Legacy full review comparisons remain available.

New NOT_FOUND answers carry zero bucket counts but retain NOT_FOUND and unknowns.
An inventory-only device can retain AFFECTED with zero known system counts. In
neither case is a zero count proof of safety or completeness.

No new database migration is required: these are additive fields in stored JSON
results and read models. Existing application/tenant authorization is not
broadened by this step; the full step-10 qualification remains outstanding.

## 4. UI behavior

The Cross-BOM cascade panel on the dependency-graph page now shows:

- Direct exposure, dependent consumer and supporting context counts/lists.
- Separate modeled exposure and review totals with formulas/precedence.
- An explicit warning that modeled relationships are not confirmed failures.
- An inventory-only linkage warning for applicable hardware answers.
- Clearly labeled legacy/unclassified answers and history entries.
- Per-category stored-run diff changes, including category moves without a total
  count change; unavailable historical classification is not presented as zero.

Process counts are labeled linked/possibly partial, and migration waves are
labeled planning/review context. This does not implement transitive process
closure (step 6) or a production migration executor.

## 5. Validation for step 1

- **103 selected backend tests passed**, including unified-engine classification,
  all target-kind invariants, cycles, multiple seeds, depth bounds, inventory-only
  device behavior, API persistence/history/watch summaries, category-only diffs,
  historical compatibility, existing source/scan/graph cases and existing cascade
  tenant-negative tests.
- **349 frontend tests passed across 37 files**, including five new panel tests
  for separated lists/totals, legacy unknown classification, inventory-only zero
  counts, historical comparison fallback and category-only diff changes.
- TypeScript typecheck and production frontend build passed.
- Existing backend deprecation/field-shadow warnings and frontend React test
  `act` warnings remain. No new warning cleanup is claimed.
- These checks do not certify live-bank behavior, actual browser interoperability,
  real Neo4j parity, load capacity, all API roles or completion of steps 2–10.

See the [implementation plan](../dev/dependency-intelligence-roadmap.md) for
remaining work. The earlier limitation guides describe the pre-step-1 baseline;
this page records the narrowly delivered change, not wholesale resolution of
that backlog.
