# Quality-only implementation progress

**Started:** 2026-10-22 UTC
**Starting commit:** `69faec96adad43848950c74c4c939151ef7b93d1`
**Branch:** `arena/bb4b80dd-cryproscan`
**Scope:** bounded implementation increments from the
[quality-only roadmap](08-execution-roadmap-and-acceptance.md). No new collectors,
BOM types, pages, services or deployment profiles.

## Current PR update — seventh increment: withdrawn source proof

Continuing guides 2/3 and roadmap B2/B3/B4 from published `7e00d37e`, existing
source-condition verification must not consume withdrawn observations. No new
feature or trust mechanism is added. The containing commit/PR identifies this
publication; [dated evidence](../readiness-evidence/quality-remediation-retraction-2026-10-23.md)
retains exact source hashes, original adverse sequence, commands and limits.

The baseline passed **68**. The complete **16-case** adverse set against unchanged
baseline source reproduced **14 failures / 2 passes**. Current eligibility now
checks live exact-estate membership of bounded frozen source comparisons. Source
intake refuses any tombstone rather than filtering it away as clean absence;
positive verification rechecks after comparison. Operator and pilot proof gates
use the same eligibility. Earlier proofs/task labels remain historical, not
silently rewritten; existing authorized/audited restore retains its separate meaning.

All **16 new cases pass**, including retraction/restore, denied/foreign paths,
other-estate preservation, repeated verification and an injected comparison
boundary. Final local checks: **480 API/assurance/remediation/six-BOM passed**, 6 warnings, **283.01 s**;
**113 auth passed**, 10 warnings, **37.85 s**; **1,159 library/package/database passed**, 10 warnings, **20.42
s**.
No failures/skips/deselections in these three runs; the 16 cases are included in
the API total, not additive. Ruff, dependency consistency, local documentation/
source-hash and whitespace checks pass. Warnings remain explicit in the record.

This is not a PostgreSQL race/fence/restore, latency/capacity, browser/site,
independent-review or customer-acceptance result. No migration, workflow, lock,
new route/collector/service/profile, native build or bank installation changes.

## Previous publication — trace integrity/freshness (7e00d37e)

The sixth increment was published in
[`7e00d37e81540f343e7d94065cff054a5962dbe2`](https://github.com/ZKChainForge/CryproScan/commit/7e00d37e81540f343e7d94065cff054a5962dbe2)
with `[skip ci]`: verify loaded relationship envelopes and both observation-time
bounds. Its original final runs were **452 API / 113 auth / 1,114 library passed**,
with **22 new cases** included in 452. Its [dated record](../readiness-evidence/quality-trace-integrity-2026-10-23.md)
is preserved unchanged; these totals are not this seventh increment's rerun.

## Previous publication — recovery and parser boundaries (9f3fa5a9)

The fourth and fifth increments were published together in
[`9f3fa5a9e873aa8f0cd44e2d16996a32154860a2`](https://github.com/ZKChainForge/CryproScan/commit/9f3fa5a9e873aa8f0cd44e2d16996a32154860a2)
on 2026-10-23 with `[skip ci]`. Their **35 + 18 new cases** are included in the
historical **1,070 passed / 16 PostgreSQL skips / 1 live Docker deselection**,
17 warnings, with a separate **113 passed** auth run, 10 warnings. Those are not
reruns for later increments. Their separate dated records remain unchanged.

## Published engineering snapshot

**Historical first-three-increment snapshot**, retained with its original scope.

**Published source:** [`2fd8fc8fba255333f605202ebb68d04c4029c610`](https://github.com/ZKChainForge/CryproScan/commit/2fd8fc8fba255333f605202ebb68d04c4029c610)
**Published:** 2026-10-22 UTC, commit message includes `[skip ci]`.
**PR:** [#34](https://github.com/ZKChainForge/CryproScan/pull/34), open at this documentation update;
not merged into main and not deployed to a bank.

The first three increments below were committed and pushed in the published
snapshot above. Its subsequent documentation reconciliation did not rerun tests.
The later increments have separate source hashes and local results; they are not
included in that first-three-increment publication or test table.

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
[historical first-three handoff](../runbooks/evidence-assurance-upgrade.md#current-quality-source-handoff-2fd8fc8f).
The previously planned interruption, duplicate-delivery and durable UNKNOWN
checks are now implemented as the bounded fourth increment below; its local
evidence does not qualify production recovery or publish a new release.
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

## 6. Fourth increment — interruption, duplicate delivery and durable UNKNOWN

**Implemented 2026-10-23; included in this PR update:** existing execution boundaries only;
no new route, collector, service, schema migration, binary build or workflow change.
The checkout contained accumulated changes before this increment; unrelated work
is preserved. The [dated record](../readiness-evidence/quality-execution-recovery-2026-10-23.md)
identifies the actually tested source by content hash; Git history identifies
the containing publication commit.

An 88-passing baseline preceded new tests. The first adverse set reproduced
11 failures among 24 cases: interrupted local pool accounting, masked original
interruptions, forbidden memory publication and transport-derived controlled job
verdicts. A separate three-case submission check reproduced three leaked semaphore
slots. Actual child-process tests additionally exposed a cold worker RBAC/dependency
import cycle that in-process API tests had masked.

Corrections release local backpressure even on BaseException, preserve the original
interruption if the UNKNOWN write fails, reject memory-only publication when fallback
is disabled, and leave controlled SQL state untouched on dead-letter notification.
Role normalization is deferred to dependency execution, breaking the cold-start cycle
without caching roles or changing the authorization matrix.

The new tests cover real SIGKILL before/after claim and after a checkpoint using a
file-backed SQLite database and independent worker/recovery processes. Repeated
recovery, stale writes, in-flight/UNKNOWN duplicates, atomic rollback and current
human/evidence confirmation remain bounded by existing contracts. Real collectors
and daemon preflight are doubles; expiry time is advanced explicitly. This is not
PostgreSQL/Docker/Redis fault, HA, latency/SLO, bank-site or customer acceptance.

Final local results: **35 new checks passed**; broader worker/selected execution
regressions **1,052 passed / 16 PostgreSQL skips / 1 live deselection**; auth
compatibility **113 passed**. The 35 cases overlap the broad run. Full configured
Python lint and dependency consistency pass. Exact warnings, timing, commands and
scope are retained in the dated record. UNKNOWN keeps its
provider/estate reservations until explicit authorized reconciliation; transport
recovery never resumes a RUNNING/UNKNOWN attempt. CONFIRMED_COMPLETED does not
manufacture a scan or findings. Any new execution requires a new currently approved
job. Independent review and actual bank recovery exercises remain open.


## 7. Fifth increment — parser startup, cancellation and cleanup

Continuing the existing controlled-runtime boundary after UNKNOWN recovery,
**72 existing boundary tests passed** before new tests. The first 14 adverse
runtime cases reproduced **9 failures / 5 passes**: raw launch errors, an unowned
child after selector-construction failure, skipped pipe cleanup after failed
kill/wait/selector close, and lost CancelledError/GeneratorExit identity.

The exchange now owns resources from startup, cleans allocated resources
independently and refuses with a safe category if cleanup cannot be confirmed.
Non-Exception cancellations propagate after confirmed named-container cleanup.
Digest pinning, fixed protocol, parser resource limits and source/SQL authority
are not weakened. Four real-SQL integration cases retain UNKNOWN and both budget
reservations after runtime/result/cleanup/cancellation failures and refuse duplicate
execution; the daemon and selected faults are explicit doubles.

The **18 new checks pass**. Final worker and authorization publication results,
source hashes, original failures, warnings/skips and exact scope are in the
[fifth dated record](../readiness-evidence/quality-parser-runtime-2026-10-23.md).
Local child tests are not Docker/escape/daemon-loss or production bank evidence.

## 8. Sixth increment — current-trace integrity and observation freshness

Loaded relationship history now uses the existing envelope verifier before
revision selection. A corrupt predecessor or storage-forged reviewed state cannot
supply a green current path. Both observation boundaries are rechecked during
review and trace, including a synthetic clock correction. Current lifecycle
revalidation and exact-estate refusal remain in force without rewriting history.

The **22 new cases** comprise six latest-envelope faults, two predecessor faults,
one forged-state fault, four trace clock boundaries, four review boundaries,
four upstream lifecycle cases and one combined intact-path/privacy contract.
All pass in the **452-case** selected API run; the separate **113-case** auth
and **1,114-case** library/package/database runs also pass. Exact commands, source
identities, the corrected red run and qualification limits are in the
[sixth dated record](../readiness-evidence/quality-trace-integrity-2026-10-23.md).

## 9. Seventh increment — source evidence withdrawal and current proof

The 16 new cases cover proposal (1), approval/report (2), first verification (2),
current read/audited restore (2), other comparison members (2), denied/foreign
withdrawal (1), unrelated estate (1), repeated verification (2), injected
comparison-boundary withdrawal (1) and pilot-status proof gating (2).

Each frozen source corpus stays bounded to 5,000 findings; every captured member
must remain live in its exact estate for current use. Historical records are
not rewritten. A last positive-result membership check is not a serializable
PostgreSQL fence or complete mutable-content proof. TLS_CERTIFICATE predicates
are unchanged. Exact results and the deliberately scoped pilot tests are in the
[seventh dated record](../readiness-evidence/quality-remediation-retraction-2026-10-23.md).

## 10. Next bounded work

1. Obtain different-human review of the bounded corrections and retain current
   source/runtime identities. No independent approval is invented here.
2. Continue observed-defect-first six-BOM wrong-build/version/estate/stale-evidence
   and authority/privacy regressions, not new collectors or feature breadth.
3. Run the approved disposable PostgreSQL/TLS Redis/actual parser/daemon/fence/
   orphan/restore fault exercises and representative browser/capacity measurements.
   Skipped or mocked checks do not close these requirements.
4. Have real site/operating owners arrange independent assessment and distinct
   technical/customer acceptance under the existing nine-duty process.

See [the full roadmap](08-execution-roadmap-and-acceptance.md) for dependencies and
[review templates](09-worked-example-and-review-templates.md) for evidence fields.
