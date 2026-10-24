# Database → API → console hardening

**Reviewed 2026-10-24 UTC. This is an implemented increment, not whole-product production qualification.**

The request was to move the existing database, backend and frontend out of demo-stage behaviour. This increment fixes a concrete durable CBOM workflow and its shared system-name contract. It does not rename the product “production-ready”, invent bank data, add collectors/services or waive release gates.

## Implemented contracts

| Layer | Previous defect | Implemented behaviour |
|---|---|---|
| Database names | `System.name` was globally unique, preventing two banks from using “Payments”. | Additive migration **0107** installs estate/name uniqueness and a separate NULL/platform unique index. Names remain exact, case-sensitive business names. |
| Unscoped name lookup | A business name could be treated as a global key. | `SystemRepository.get_by_name` explicitly uses the current tenant; an unset tenant means platform, not all banks. |
| Migration safety | Unit `create_all` did not prove the live UNIQUE constraint was removed. | Handles the actual 0012 `uq_systems_name` constraint and historical model-created index shape. Real PostgreSQL tests cover fresh chain, populated upgrade, NULL uniqueness, bounded lock acquisition failure/transaction rollback, downgrade/re-upgrade and refusal to downgrade duplicated names. |
| Write authority | Import required login but no write role. | Durable-role checks allow `superadmin`, `ciso`, `security_analyst`; readonly/auditor/developer/scanner/business-owner/supervisor imports are denied. Existing tenant/authentication and production execution controls remain in force. |
| Untrusted request | CBOM JSON lacked the assurance workflow's pre-parser body bound. | Reuses the existing bounded evidence middleware: **2 MiB wire cap**, duplicate-key/nonfinite/over-nested JSON rejection, chunked-body checks and `no-store`. Runs before policy/body parsers. |
| Import profile | Supported and unsupported native structures could be conflated. | 1.6 uses the pinned full schema/reference validator. This inventory import accepts **flat algorithm metadata**. Nested documents and native certificate/key/protocol components are rejected explicitly, not silently flattened or misrepresented as algorithms. Legacy 1.4/1.5 metadata is checked defensively; this is not full legacy schema qualification. |
| Field bounds | Valid JSON could exceed real PostgreSQL column/integer limits. | Validates system/owner/environment lengths, algorithm/purpose/mode/padding limits, integer ranges, finite JSON and bounded scalar business context before writes. Conflicting declarations at one inventory identity are rejected. |
| Signatures | The ingest gate looked only for legacy signature properties. | Also verifies top-level JSF signatures; unsupported/empty envelopes fail closed. A required, locked URI-format validator fixes JSF `oneOf(JWA enum, URI)` validation when jsonschema's optional URI checker was absent. Integrity checking is **not issuer/bank trust**. |
| Observation truth | Uploaded metadata was stamped HIGH/CURRENT with a scan timestamp. | New imports are LOW-confidence declarations, with `IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS`. They do not create scans or change scanner timestamps, coverage status, scan failure or last scan ID. |
| Source separation | An import could overwrite a matching scanner asset or another application's context. | New imports use an explicit per-system observation namespace inside existing asset metadata. Scanner refreshes and other systems' imports are separated. This is not a new physical-asset identity or proof of deployment. |
| Persistence | Business context/PQC parameters were discarded, mode/key size stayed stale, repeated batch keys could insert duplicates. | Persists allowlisted business contexts, reported PQC parameter/unit basis, source fingerprint and padding; refreshes mode/key size; de-duplicates matching rows. Native readback/export retains these declarations. |
| Receipts/audit | Import provenance was immediately overwritten by `stamp_scan`; a request-scoped commit could happen after success was delivered. | Separate durable `extra.cbom_import` receipt survives later scan stamping. Existing scan metadata is preserved. Import and metadata-only `cbom.ingest` audit entry commit **before** HTTP success; errors roll back. No raw document or secret material is added to the audit detail. |
| Concurrent writes | Two requests could race on a new or existing system. | Existing system imports take a row lock and refresh the locked state; first-create conflicts return **409**. Storage failures return **503 / outcome unconfirmed**, not a promise that nothing committed. |
| Console workflow | No upload/readback path on the existing CBOM page. | Authenticated file import, committed receipt/fingerprint, refreshed inventory and authenticated persisted export. Client file cap **1 MiB**; server remains authoritative. Absent components are **not automatically retired**. |
| Private UI state | Old queries/pins/views/diffs could outlive an estate or scan selection. | Private-scope remount/current-context fences, selection generations and view/diff request fences. Clears drafts and stale state; no automatic write replay. A late receipt is discarded, not presented as a rollback. |
| Coverage display | Unavailable coverage was rendered as zero; “active CBOMs” conflated inventory with scans. | Unknown when the coverage request fails; labels recorded **current-or-stale scan** coverage and explicitly excludes imports. This percentage is not discovery completeness. |

## Evidence, not a readiness label

See [execution and retained records](../readiness-evidence/production-data-path-2026-10-24.md):

- **974 selected Python tests**, no failures/errors/skips; four existing warnings.
- **561 frontend tests / 53 files**, no failures; 20 existing React `act` warnings remain.
- **10 real PostgreSQL migration checks**, no skips.
- **16 actual Chromium/browser/database checks**, including real password sessions, native file upload, readback/export, four simultaneous existing-system writes and a first-create race.
- **4 post-restart checks**, using the saved HTTP-only session after both API and PostgreSQL restart; changed postmaster timestamp, refused connections while stopped, retained committed data.
- Frontend typecheck/build, changed-Python Ruff F checks, dependency consistency and diff whitespace checks pass.

This is not a full repository test run, container build, deployment, security audit, accessibility/Arabic acceptance or performance benchmark. Four concurrent requests are not a capacity test. Agreed p95/p99/relative engineering targets were **not re-measured or re-qualified** here; there is no caching/architecture-first performance claim.

## Scope and important remaining engineering work

1. **Historical data needs review.** Old imports may already have HIGH/CURRENT labels and lost source context. This migration does not fabricate original fingerprints, automatically relabel/clone old assets, erase history or infer which old rows were genuinely measured. Re-import original documents into the new declaration namespace and explicitly reconcile legacy rows under the existing evidence-disposition/review process. Older mixed import/scanner rows must not be accepted as independent observations merely because they predate this release.
2. This is an **append/refresh metadata import**, not lossless arbitrary CycloneDX import, full graph/material import, request-ID exactly-once processing, automatic retirement, measured PQC interoperability or certificate/key ingestion. Repeat imports can append repeated audit events while retaining asset identities.
3. The existing audit repository is used transactionally. The browser check verifies persisted receipt/audit rows, **not independent approval or qualification of the entire concurrent global audit chain**.
4. The [original 45 engineering-gap matrix](bank-original45-engineering-gaps.md) still applies: broader discovery, legacy/mainframe/payment/binary/runtime qualification, measured migration/HSM/PQC behaviour, parameter-unit handling across remaining consumers and independent completeness remain unfinished. The separate universal-crypto corpus accuracy conventions were not changed here.
5. NBOM, CBOM, TechBOM, HBOM, VBOM and SBOM remain **six distinct BOMs**; this increment does not close every source/adapter or turn a projection into independent evidence.
6. Production settings/control-surface restrictions were not relaxed. The browser exercised a **production-compiled console with development API settings** on disposable PostgreSQL, not an activated production deployment. The UI's “PRODUCTION” environment selector is an estate data filter, not runtime qualification.
7. No customer deployment was modified. Supported production PostgreSQL/Redis, TLS, encrypted/resident storage, approved execution/isolation, backup/PITR/HA/partition drills, capacity, image/CI/security review, independent bank acceptance and real staffing/support/commercial obligations still require their own evidence. The strict original-question register remains blocked.

Follow the [0107 upgrade/rollback runbook](../runbooks/cbom-0107-upgrade.md). The engineering evidence does not authorize a rollout or replace the unified [production gate](../../PRODUCTION-READINESS.md).

## Follow-up: historical provenance and audit serialization

The next [implemented increment](historical-cbom-reconciliation.md) adds bounded
historical review/reconciliation, conservative source-aware current coverage,
namespace collision fixes, SQL-bounded portfolio reads and PostgreSQL audit-append
serialization. Its [fresh execution](../readiness-evidence/historical-cbom-2026-10-24.md)
supersedes the historical/audit implementation gaps above only to that explicitly
described extent. Mixed-source/unassigned cases, independent qualification and the
remaining original-45 capabilities are not declared closed.
