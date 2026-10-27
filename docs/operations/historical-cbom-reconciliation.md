# Historical CBOM reconciliation — implemented increment

**Successor:** [controlled unassigned/mixed-source decisions](controlled-historical-cbom.md)
now extend the existing workflow. Retained mixed histories remain partial, not
clean scan evidence or bank acceptance. Earlier limits/results below describe
the historical increment.

**2026-10-24 · existing database → API → CBOM console. Not whole-product production qualification.**

This follows [data-path hardening / migration 0107](production-data-path-hardening.md).
It improves existing inventory/review/export workflows; it does not add a collector,
service or dashboard. NBOM, CBOM, TechBOM, HBOM, VBOM and SBOM remain six distinct BOMs.

## What changed, and why

| Gap | Implemented behaviour | Important boundary |
|---|---|---|
| Historical imports could still report HIGH confidence. | Import markers and malformed/incomplete import receipts receive conservative read projections: `confidence=LOW`, `reported_confidence` retained, and `source_basis=LEGACY_IMPORT_REVIEW_REQUIRED`. Modern receipts remain explicitly imported declarations. | Raw confidence, scanner IDs, findings, evidence hashes and signatures are not rewritten. A marker is **not** proof that no scanner evidence exists. Lost provenance cannot be reconstructed. |
| An old import stamp could appear as a current scan. | System catalog, system read/list APIs, coverage summary and coverage filters use source-aware coverage. Without a completed same-tenant referenced scan, legacy coverage is unproven; a target is NEVER_SCANNED, no target is NO_TARGET. FAILED remains FAILED. With a genuine completed referenced scan, its actual start/end time is used, not the import's newer timestamp. | Old timestamps/status remain available as `reported_*` fields and in stored history. A completed scan is not proof of discovery completeness or bank acceptance. |
| Operators had no safe path to separate historical declarations. | The existing CBOM page now lists pending systems, loads bounded source reviews, shows the replacement fingerprint, requires an explicit rationale/acknowledgement and displays the committed audit receipt. | Readonly users cannot write. Reimport is an operator-reviewed replacement declaration, not proof that the original document was independently authenticated or the deployment observed. |
| Cleanup could erase or misclassify real evidence. | Reconciliation refuses **any linked evidence**, incomplete replacement identity coverage, stale snapshots, missing current replacement receipts, and oversized reviews. It removes only reviewed system–asset associations and archives only unshared, unmeasured historical declarations in existing metadata. | Original assets and evidence remain. Shared rows stay active for the other systems. Mixed-evidence, unassigned and oversized cases require controlled operator investigation; this increment does not supply an automatic resolution for them. |
| Export could silently treat unresolved history as clean current data. | System/portfolio/custom current CBOM export and stored-system/portfolio assessment paths refuse unresolved historical rows with 409. Portfolio checking includes pending records beyond the returned row cap. A later evidence link makes an archived declaration pending again. | Read/list review and retained inventory remain available. Pinned historical documents are not silently rewritten. Inline document assessment remains document analysis, not deployment verification. TechBOM/cross-BOM current projections carry conservative source labels; their historical snapshots are not retroactively certified. |
| Scanner/cloud updates could overwrite imported records. | Scan refreshes exclude both legacy and modern import namespaces; cloud lookup excludes imports even at the same file path. Archived historical declarations cannot be reattached through the system repository. | This addresses import collisions, not every possible pre-existing duplicate/provider-reference collision. |
| Portfolio limits were applied after loading everything. | Located asset rows are now ordered and limited **in SQL**; a window count reports the full matching count from that same statement. | The limit counts located rows (including per-system associations), not unique physical assets. Functional SQL-bound tests are not a performance/capacity benchmark. |
| Concurrent audit appends could fork the global chain. | PostgreSQL appends obtain one transaction-scoped advisory lock **before** reading the global head, held until commit/rollback. Non-READ-COMMITTED PostgreSQL appends fail closed. | Cooperative application writers only; no DB-admin-proof immutability, historical-fork repair, SQLite concurrency qualification or throughput guarantee. Stop old/uncooperative writers before rollout. |

## Database and API contract

No new table or migration is required: schema head stays **0107**. Existing JSON
metadata, system–asset associations and the global audit table persist the decision.
The audit entry includes actor, system, source snapshot hash, replacement hash,
reviewed asset IDs and rationale. Do not paste secrets into the rationale.

- `GET /api/v1/cbom/legacy-imports?page=1&page_size=50`: paged pending systems,
  total and an unassigned-pending count; maximum page size 200.
- `GET /api/v1/cbom/system/{id}/legacy-imports`: snapshot hash, replacement
  fingerprint, bounded asset identifiers/algorithms, historically reported confidence
  and linked-evidence counts. Does not return arbitrary extra data or raw findings.
- `POST /api/v1/cbom/system/{id}/reconcile-legacy`: writer roles are superadmin,
  CISO or security analyst, as for import. Body:

```json
{
  "expected_snapshot_sha256": "<64 lowercase hexadecimal characters from the current review>",
  "replacement_document_sha256": "<current replacement receipt SHA-256>",
  "reason": "Human review rationale, 20–500 characters after trimming surrounding whitespace"
}
```

The placeholders above are descriptive, not a directly executable request.
Review is limited to **2,000 legacy rows and 2,000 replacement rows per system**;
excess returns 413, never a truncated approval. Replacement coverage checks all
historical `(algorithm, purpose, file_path, line_number)` identities, not equality
of every old attribute. Correcting declared parameters is allowed; the operator
must review the actual document and changes.

A successful write locks/refetches the system and legacy assets, validates the
snapshot, records the audit, detaches reviewed associations, archives only rows
with no remaining system links, and **commits before HTTP 200**. PostgreSQL row
locks serialize conflicting reviews. 409 requires a fresh review; database
failure returns 503 with **outcome unconfirmed**. A lost response is not proof
that nothing committed. Never automatically replay a write; reconcile inventory
and audit first. Client context fences discard stale private state, not server commits.

Coverage exposes `legacy_coverage_unproven` separately from inventory-review
counts. Reconciliation does not create a scan or increase scan coverage.

## Verified execution

See [execution, retained artifacts and exact scope](../readiness-evidence/historical-cbom-2026-10-24.md):

- 1,020 selected Python tests; 568 frontend tests across 54 files.
- 27 real PostgreSQL checks: 13 source-classification cases, four audit concurrency/
  rollback/isolation controls, and ten migration checks.
- 17 real Chromium reconciliation checks and 16 existing import/export regression checks.
- Typecheck, production frontend compilation, Ruff, dependency consistency and whitespace checks.

Four Python warnings and 20 existing React `act` warnings remain. This is not an
all-repository, CI, image, production-settings, independent security/accessibility,
Arabic, bank-acceptance, DR or capacity certification. Agreed relative performance
and p95/p99 targets have **not** been remeasured here; no caching was introduced.

## Rollout and next steps

Use the [operator runbook](../runbooks/historical-cbom-reconciliation.md). In particular,
stop old writers, retain a verified backup and fully verify the pre-existing audit
chain before enabling the new flow. Existing forks are an investigation, not a
permission to rewrite signed or committed evidence.

Remaining implementation work includes controlled mixed-source/unassigned review,
broader source qualification and parameter-unit consumers, and deployed failure/
capacity/security qualification. Continue against the [original-45 engineering
matrix](bank-original45-engineering-gaps.md) and [production gate](../../PRODUCTION-READINESS.md),
not a new readiness percentage. This increment does not make every original
capability or the separate acceptance register pass.
