# Quality-only implementation progress

**Started:** 2026-10-22 UTC
**Starting commit:** `69faec96adad43848950c74c4c939151ef7b93d1`
**Branch:** `arena/bb4b80dd-cryproscan`
**Scope:** bounded implementation increments from the
[quality-only roadmap](08-execution-roadmap-and-acceptance.md). No new collectors,
BOM types, pages, services or deployment profiles.

## Published engineering snapshot

**Published source:** [`2fd8fc8fba255333f605202ebb68d04c4029c610`](https://github.com/ZKChainForge/CryproScan/commit/2fd8fc8fba255333f605202ebb68d04c4029c610)
**Published:** 2026-10-22 UTC, commit message includes `[skip ci]`.
**PR:** [#34](https://github.com/ZKChainForge/CryproScan/pull/34), open at this documentation update;
not merged into main and not deployed to a bank.

All three increments below are committed and pushed. The current docs-only
follow-up corrects publication/operating guidance; it changes no implementation,
workflow, dependency lock or schema and does not rerun the application tests.

| Final checks retained for the published source | Actual result |
|---|---|
| Selected API/auth/estate/queue/assurance/six-BOM suites | **641 passed**, 12 warnings |
| Shared-model/full-CBOM/selected-SBOM/package/database-gate suites | **1,146 passed / 1 skipped**, 26 warnings |
| Full frontend DOM suite | **398 passed / 45 files** |
| Toolchain | **7 passed** |
| Typecheck, production bundle, Python lint and dependency consistency | Passed |

The skipped disposable-PostgreSQL case requires `pg_virtualenv` and explicit
opt-in. It is not evidence of a passed PostgreSQL exercise. These scoped local
results are not all-repository, GitHub Actions, real-browser/site, independent
security or bank-production qualification. Counts from earlier incremental runs
below overlap and retain their original scope; do not add them together.

For upgrade consequences and safe operator responses, use the
[current handoff](../runbooks/evidence-assurance-upgrade.md#current-quality-source-handoff-2fd8fc8f).
The next bounded engineering work is interruption, duplicate-delivery and durable
UNKNOWN recovery checks; it is **planned, not implemented by this docs update**.
Different-human review and real site/customer acceptance remain pending.

## 1. Sequence actually followed

1. Freeze the current controlled local-source/v1 → registered coverage → existing
   operator/assurance read workflow. Retain all six BOMs and deliberately refused
   collection interfaces.
2. Run the selected existing authenticated assurance/operator/controlled-boundary
   baseline: **57 passed**. This is a local SQLite baseline, not a whole-system result.
3. Write adverse-case tests first. Reproduce false source coverage before fixing it.
4. Harden source coverage intake and current reads without rewriting history.
5. Reproduce and remove the documented remote font bootstrap/CSP allowances.
6. Run focused/related backend and frontend checks; retain exact results in the
   [dated engineering record](../readiness-evidence/quality-increment-2026-10-22.md).
7. Different-human review remains pending. No reviewer, bank permission or
   accepted production outcome is invented by this work.

## 2. Implemented changes

| Item | Reproduced problem | Bounded correction | Status |
|---|---|---|---|
| Q01/Q02 — source coverage evidence | A truthy receipt list such as `[{}]`, failed parser outcome, missing checksum or incoherent job/scan interval could record OBSERVED. Existing green coverage survived invalidated backing SQL evidence. | Validate typed bounded unambiguous primary-file receipts, actual parser success, checksum/file identity, exact job/scan/target and coherent completed intervals. Revalidate current evidence on reads; fail with 409 rather than return false green counts. | Implemented; local validation results in dated record; independent review pending. |
| Q05 — avoid query amplification from the correction | Current-source revalidation could introduce one lookup per target if implemented naively. This is a regression risk, not a claim of a pre-existing N+1 defect. | Batch job/scan lookup per register; ten observed source targets use exactly two proof queries in the SQL fixture regression. | Regression added; not a PostgreSQL capacity benchmark. |
| Q03/Q06 — on-prem browser bootstrap | Entry HTML linked Google Fonts/preconnects, and runtime CSP explicitly allowed external font/stylesheet origins. | Remove the remote bootstrap references and CSP allowances; use existing local/system font fallback stacks. Add entrypoint/CSP contract regressions to the existing toolchain tests. | Implemented; real bank-browser/no-egress acceptance remains open. |

### Important behavior and compatibility notes

- `OBSERVED` still means eligible observed evidence for a registered target, **not**
  complete source coverage, independent invocation/deployment truth or whole-bank safety.
- Partial primary-file coverage does not become `collection_complete=true`.
- Malformed/missing/invalidated source proof returns **409** on current coverage
  reads, including dependent operator summaries. It does not silently keep old
  OBSERVED counts, edit/delete history or manufacture a successful empty report.
- An old positive source observation without eligible backing proof needs an
  actual valid collection/observation under current authorization. Inspect retained
  history; never patch database receipts or reset job states to restore a green view.
- Current source-proof validation uses bounded batched SQL reads. It does not
  qualify performance at bank scale or other collection adapters.
- Frontend fallback-font appearance requires the bank's actual browser/RTL/zoom
  review. Removing known Google references does not prove every runtime path is
  offline, no telemetry exists, or an old deployed image is updated.
- Rebuild coordinated application/frontend images and externally verify/re-sign
  the intended full package before site deployment. There is no schema migration
  or automatic production rollout in this increment; schema head stays 0105.

### Local validation snapshot

- Related backend/assurance set: **194 passed**, including **33 new regressions**.
- Package/signature/guarded migration checks: **24 passed**.
- Full frontend DOM suite: **398 passed**; toolchain: **7 passed**.
- Typecheck, production bundle, full Python Ruff check and documentation validation passed.

These are separate scoped runs, not a whole-system or bank-production qualification.
Exact conditions, original red results and warnings are in the dated record.

## 3. Roadmap state, without inflated completion claims

| Roadmap area | Current result | Still required |
|---|---|---|
| A1 scope | Engineering scope/non-goals frozen for this increment | Actual bank charter/site authorization and named owners |
| A2 baseline | Selected baseline and adverse reproductions retained | Complete intended release/environment baseline, not just these suites |
| A3 objectives | Receipt invariants and a bounded query-count objective are explicit | Bank-approved accuracy, PostgreSQL/resource/browser/recovery objectives |
| B1/B4 | Source coverage defect corrected with focused and related regressions | Remaining six-BOM correctness matrix and independent review |
| B3/C3 | Known external browser bootstrap dependency removed; role-store failure and selected public probe/log privacy corrected with negative regressions | Full critical security/accessibility/user/browser acceptance matrix and different review |
| C1/C2/C4 | No broad recovery/refactor/capacity work claimed | Intended-site fault, recovery, capacity and maintainability work packages |
| D | All three increments pushed in `2fd8fc8f` with `[skip ci]`; no workflow changes, signed release or site update | Actual required checks, signed full package, migration/recovery rehearsal |
| E/F | Not performed | Real independent assessor/owners/site/customer evidence and current approval |

The user retains responsibility for the earlier unspecified workflow failure.
No Actions result is independently confirmed, no check is waived and no CI run
is dispatched here. No readiness percentage, SLA, certification or all-roadmap
completion is claimed.

## 4. Second increment — unresolved package identity

Continuing roadmap B1/B2/B4 and Q01/Q02, a new **136-passing-check** baseline
was captured before changing package identity. The initial adverse set had
**29 failed / 6 passed**: known variable/wildcard/interval versions were being
treated as exact identities. Legacy reviewed associations and old cascade
projections retained that mistake. A paired three-case check also reproduced
an inconsistent legacy unresolved count in the provisional fix.

The existing identity helper now refuses those known unresolved forms after
PURL decoding. CycloneDX/SPDX normalization preserves source metadata and counts
the packages unresolved. Current application trace/review and cascade projections
re-evaluate old derived identities; historical documents, reviews and snapshots
are not rewritten. Explicit artifact/deployment evidence remains usable and is
not relabeled independently verified runtime evidence.

| Local check for increment 2 | Result |
|---|---|
| Added regression cases | **38 passed**; includes concrete-version compatibility and valid-signature/unknown-package safety |
| Shared-model + full CBOM + selected SBOM library suites | **1,113 passed**, 4 warnings |
| Related API/assurance/SBOM/TechBOM/HBOM/VBOM suites | **256 passed**, 4 warnings |
| Full Python Ruff check | Passed |

These runs overlap. No frontend rerun, bank accuracy rate, PostgreSQL/browser
capacity, independent approval or complete six-BOM matrix is claimed. The earlier
frontend and package/migration results above remain attributed to increment 1.

**Compatibility:** unresolved legacy PACKAGE_CRYPTO proposals now refuse review
with 409; reviewed legacy edges cannot fill current exact-package paths. Original
history stays readable. The changed helper changes the existing offline supplier
engine fingerprint, so old exercised qualifications must be re-exercised under
the approved exact profile, not patched into currency. No schema migration,
workflow edit, new range engine, new API or live-vendor support is introduced.
Different-human review and actual site qualification remain pending.

See [increment 2's exact evidence](../readiness-evidence/quality-package-identity-2026-10-22.md)
for original failures, source identities, execution commands and limitations.

## 5. Third increment — authority failures and safe health diagnostics

Roadmap B3/B4 and Q03 now have a further bounded correction. The selected baseline
passed **27 checks**. An expanded 36-case adverse set reproduced **31 failures /
5 passes**: unavailable role storage could enter the legacy admin fallback,
missing production identities could use legacy scope handling, disabled/deleted
rows could supply roles, and public probe/selected failure-log paths could expose
a synthetic connection-secret canary.

Unavailable role storage now refuses with **503** instead of granting compatibility
authority or using stale token roles. Production missing identities and current
disabled/deleted rows cannot supply those role/platform grants. Affirmative absent
non-production legacy compatibility remains supported. Selected role/scope/database
failure logs and public probes retain safe event/category/status metadata instead
of driver messages, SQL, connection strings and tracebacks.

| Local check for increment 3 / accumulated publication | Result |
|---|---|
| New authority/scope/probe/privacy cases | **40 passed**, including four real-session artifact-route safety cases |
| Expanded API/auth/estate/queue/assurance/six-BOM suite | **641 passed**, 12 warnings |
| Shared-model/full-CBOM/selected-SBOM/package/database-gate suite | **1,146 passed / 1 skipped**, 26 warnings |
| Full frontend DOM suite, rerun for publication | **398 passed** |
| Toolchain checks | **7 passed** |
| Frontend typecheck and production bundle | Passed |
| Full Python Ruff check, dependency and documentation checks | Passed |

The skipped existing test needs `pg_virtualenv` and an explicitly disposable
PostgreSQL fixture; it is not passed or waived. Tests overlap across focused and
broad runs. The isolated role-gate reproduction overrides the already-authenticated
principal; the four added actual artifact-route cases use real durable synthetic
sessions and targeted post-login storage faults. Neither is a real outage,
end-to-end login exploit or bank-site qualification. This is not an all-log audit.

Details, original failures, exact check scope and source identities are in
[increment 3's engineering record](../readiness-evidence/quality-authority-privacy-2026-10-22.md).
All three accumulated increments were published in `2fd8fc8f` to the current PR
branch with `[skip ci]`, without workflow edits or resolving the earlier CI lane.
A source push does not update a bank installation or sign a full operator release.
Different review and all actual site/security/customer acceptance remain open.

## 6. Next bounded work

After review of these increments:

1. Continue the six-BOM wrong-build/version/estate and stale-evidence matrix,
   starting with an observed defect or explicit missing proof, not feature breadth.
2. Continue authority/privacy boundary coverage beyond the selected role/probe
   paths and rehearse durable UNKNOWN/interruption/duplicate-delivery recovery
   using existing test boundaries; retain original outcomes.
3. Run the proposed PostgreSQL/browser measurements only in an approved isolated
   representative environment. Local SQLite and DOM tests cannot substitute.
4. Have real owners arrange independent assessment, site evidence and operating
   exercises in parallel; these cannot be assigned to fabricated identities.

See [the full roadmap](08-execution-roadmap-and-acceptance.md) for dependencies and
[review templates](09-worked-example-and-review-templates.md) for evidence fields.
