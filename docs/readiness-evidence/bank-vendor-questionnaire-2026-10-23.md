# Bank PQC questionnaire — executed gap fixes and remaining acceptance

**2026-10-23 UTC · PR34 · branch `arena/bb4b80dd-cryproscan`.**
Baseline: published `5a686ed2e4f38db29b1dd449984dafb0dab43d91`.
This is bounded engineering execution, **not “all bank requirements complete.”**
No new service, screen, collector, production scan or customer deployment.
Publication uses `[skip ci]`; no workflow/main changes or CI-green claim.

## Deliverables

- [Detailed answers: all45 original questions plus12 additional controls](../operations/bank-pqc-vendor-questionnaire.md).
- [Safe technical, operational and procurement acceptance playbook](../operations/bank-pqc-vendor-acceptance-playbook.md).
- [Machine-readable57-item source/gap register](../operations/bank-vendor-questionnaire.json).
- [`scripts/bank_vendor_questionnaire.py`](../../scripts/bank_vendor_questionnaire.py):
  executable register integrity/source-path/hash review; strict mode fails while
  bank acceptance is open. A valid register is explicitly **not** qualification.
- [Execution records and reproduction](bank-vendor-questionnaire-2026-10-23/README.md).
- [Results/source/record hashes](bank-vendor-questionnaire-results-2026-10-23.json).

## Demonstrated product defects fixed

| Existing surface | Before | Implemented behavior |
|---|---|---|
| Unified inventory quantum posture | Substring matching could treat prestandard names as ready or hybrid names as classically vulnerable. | Shared registry/classifier, unknown stays unknown, explicit `pqc_candidate`, `hybrid_candidate`, `symmetric_candidate`; no deployed-ready claim from names. |
| Banking unknown algorithm | Unknown/custom names fell through to `quantum_vulnerable:false` and “no known quantum break.” | `quantum_vulnerable:null`, transition unknown and review required. Unassessed/empty HNDL scope cannot become a no-risk conclusion. |
| HSM/FIPS readiness | Any capability text mentioning PQC became ready; manufacturer/family lookup or supplied assertion became validated. | Unverified declarations/mentions retained, including negated/roadmap text, but verified PQC count stays0; module validation stays unknown/declared-not-verified. No exact module/firmware/runtime/certificate qualification is invented. |
| Risk/planning algorithm names | Arbitrary `ML-KEM-*`/`AES-*` strings could trigger safe-family branches; hybrid aliases missed. | Registry recognition required; nonapproved PQC candidates require review. Hybrid algorithm candidates counted separately from verified deployment readiness. |
| Mosca inputs | Negative, boolean, infinity and NaN could be scored or create a misleading margin. | Strict finite nonnegative bounded inputs in API **and** direct function; unknown extra API fields refused. Scenario/threat-year assumption explicitly labeled, not a forecast or mandate. |
| HNDL purpose/unknown data | Signature-only use treated as harvested ciphertext; missing retention/algorithm and empty portfolio could read as no/low risk. | Signature-only authenticity migration remains in roadmap but not ciphertext HNDL; missing facts and empty/unassessed portfolio remain UNKNOWN. |
| Regulatory deadlines | General DORA/PCI effective dates inserted as quantum migration deadlines; leap-day model arithmetic could throw. | No automatic regulatory dates from framework names. Engineering deadline assumptions and historical draft roadmap basis explicit; leap-day planning works. Actual current legal/standards applicability still requires review. |
| Migration plan input cohort | A one-shot iterable could be consumed before workstream/retention processing. | Snapshot findings/systems once so portfolio, workstreams and Mosca see the same cohort; generator/list equality regression. |
| Worker persisted summary | Candidate identity/readiness and scenario boundaries could be lost in projection. | Candidate count, NOT_ESTABLISHED readiness, model assumptions and Mosca scenario basis retained in scan statistics. |
| Existing Banking view | Failed/unknown reads displayed “zero vulnerable”; absent jurisdiction data substituted10; evidence survived estate switch; jurisdiction was sent as an unsupported framework. | Loading/unavailable/unknown/returned-empty separated; actual mapping count or unavailable; existing private-scope boundary clears old-bank evidence; correct jurisdiction parameter. |
| Existing Banking labels | ISO signature parser called verification, name detection called PQC readiness, mappings presented as regulatory authority. | Explicit signature **metadata** label, algorithm screening without trust/implementation claims, crosswalk review rather than approval. |

These fixes close demonstrated misleading result paths, not all coverage gaps.
A candidate name is still not evidence of negotiation, correct implementation,
module validation or a complete estate. Supplier/HSM declarations remain review
leads, not verified facts. Existing broader legacy readers, imports and reports
are **not universally requalified** by this selected pass.

## Actual adverse evidence and regressions

1. Initial39 new bank-boundary cases: **37 failed /2 passed** before changes.
2. Five added purpose/deadline/empty-scope checks after initial fixes:
   **4 failed /40 passed**. Empty/unknown HNDL was already fixed; not a new win.
3. Seven added risk/portfolio/one-shot-input checks: **5 failed /46 passed**.
   Two nonapproved names already stayed unknown in that engine.
4. Six new Banking view checks: **6 failed**, then **6 passed** after fixes.
5.13 new register checks exercise completeness, missing/duplicate IDs, absent
   answers/sources, unsupported approval, traversal/symlinks and fail-closed mode.
   These are new regression contracts, not13 claimed pre-existing defects.

The final bounded suite contains **648 passing Python tests,4 warnings, zero
skips**: complete CBOM service tests, quantum service tests, registry/classifier,
banking APIs, ISO20022/KMIP, bank dependency security, agility, quantum API,
worker quantum projection and new bank/question-register cases. Four HTTP422
cases additionally verify invalid Mosca requests are not scored.

The separate current six-BOM negative matrix also passed **21 cases /4 warnings**,
with zero skips, covering distinct SBOM, CBOM, NBOM, TechBOM, HBOM and VBOM
evidence boundaries. It is separate from the648-case selection, not an acceptance score.

**Full frontend:548 passed /52 files**, zero skipped cases in JUnit, including
six new Banking view cases. Typecheck and production build pass.20 existing
React `act` warnings remain in CriticalScope/Tenancy, not hidden by filtering.
Python warnings: existing auth Pydantic Config deprecation, two request models'
`register` field shadowing, and TestClient/httpx deprecation. No blanket warning
suppression or skipped qualification was used.

Existing tests that asserted declaration==ready, family==validated,
signature==ciphertext-HNDL or framework-effective-date==PQC-deadline were changed
to assert the corrected distinctions, not deleted to keep a green count.
Authenticity risk still has its own migration wave. Passing totals are not a
bank acceptance score and are not all repository tests.

## API/client compatibility notes

- `quantum-risk-v2.1` identifies changed scoring/assumption semantics.
- Inventory `pqc` no longer emits `ready`; clients should handle candidate and
  unknown categories rather than treating any non-vulnerable value as safe.
- `quantum_vulnerable`, HNDL `at_risk` and HSM `ready_share` can be null where
  facts/qualification are unknown. Frontend contracts reflect those nulls.
- `pqc_ready_count`/`pqc_ready_sites` remain0 for verified deployment readiness;
  use new candidate counts for algorithm screening. HSM declarations have a
  distinct unverified count. These functions do not authenticate runtime proof.
- Supplied FIPS assertions preserve their claimed status/cert as declarations,
  but no longer return verified status. Family lookups never establish it.
- New basis/readiness/assessment fields travel through overview and worker
  summaries. Clients must preserve them and not coerce unknown into false/zero.
- No database migration was added and historical stored results were not rewritten.
  Recompute current status under the new calculation version; do not relabel old
  snapshots as newly qualified. Strict clients need an explicit compatibility review.

## What this did not build or establish

The57-item register deliberately reports `BLOCKED_FOR_BANK_ACCEPTANCE`,
`bank_approved:false` and `discovery_completeness_proven:false` even with valid
source navigation. It documents exactly what remains: product/version-specific
coverage; inaccessible SaaS/third-party/legacy systems; labeled accuracy corpus;
real handshake/HSM/PQC performance and interoperability; bank-owned classification
and denominator; integration delivery/revocation; air-gap/runtime/security tests;
actual corporate certifications, customer references, partnerships, finance,
pricing, staffing, support/SLA, residency and verifiable exit agreements.

No actual comparable-bank report/CBOM, independent current CycloneDX schema
qualification, live standards update verification, native browser/assistive-tech
acceptance or real bank pilot was performed here. Native PostgreSQL/recovery
and built-Chromium records from earlier increments remain **historical** and
were not rerun for this pass. No production/network/HSM/cloud/customer data was
accessed and no universal precision/recall or full-discovery claim was made.

## Publication integrity

The restored checkout initially presented prior published files as a large dirty
patch against the original shallow base. Every published PR file was compared
by Git blob bytes: only this pass's nine then-modified existing files differed.
Pre-pass snapshots also matched the PR tip; no pre-existing staged work existed.
Local branch/index metadata was aligned to the already-published tip **without
changing working files**, preserving this pass's edits. Only the current delta
is published; no unrelated workflow or deployment patch is swept into it.
