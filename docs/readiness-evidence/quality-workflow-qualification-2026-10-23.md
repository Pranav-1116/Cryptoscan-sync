# Ninth quality increment: coordinated workflow qualification — 2026-10-23 UTC

## Scope and provenance

Starting published source: `78d4df9114e7cd3e98609c38b1ae6cd5d40d3ea2`, branch
`arena/bb4b80dd-cryproscan`, [PR #34](https://github.com/ZKChainForge/CryproScan/pull/34).
This continues the existing-product roadmap: connected workflow, private browser
state beyond Remediation, and **executed disposable PostgreSQL** exercises.
It adds no collectors, BOM types, pages, services, deployment profiles or CI lanes.
The additive migration is **0106**. Publication is not deployment or approval.

Read alongside the [PostgreSQL record](quality-postgres-workflow-2026-10-23.md),
[browser record](quality-critical-browser-2026-10-23.md), and retained
[machine-readable results/input hashes](quality-workflow-results-2026-10-23.json).
Older increment reports remain historical, including their earlier explicit gaps.

## Observed problems and bounded corrections

| Observation | Correction / why |
|---|---|
| Native PostgreSQL `scanjobstatus` rejected UNKNOWN, although repositories use that outcome to retain uncertain work. Enum comparisons also need existing DEFERRED/CANCELLED identities. | Add those three labels in 0106, without relabeling jobs, resetting attempts, releasing budgets or creating approvals. Package preflight expects 0106. |
| A concurrent soft withdrawal could commit after the positive comparison check but before proof commit. | Lock the sorted union of **all captured before/after evidence members**, not just the selected two; recheck current membership while locks are held. Four native blocking-order exercises cover the withdrawal positions. Not a universal serializability claim. |
| Real source analysis normalizes SHA-256 to SHA2 plus width, so literal-only comparison could not establish the intended replacement. | Wire the existing exact-identity predicate: normalized SHA2 requires an exact approved integer width; explicit literal identities stay distinct. SHA-384 cannot satisfy SHA-256. Twelve pure predicate cases accompany the source journeys. |
| The controlled profile refused the narrow existing finding/history reads needed by the supported workflow. Optional tenant-middleware absence also made the admission check inspect owner=None. | Qualify only the existing GET list/detail/verify and scan JSON export paths required here; resolve trusted owner in the admission thread, enforce exact owner and residency again at reads. Do not open broad CSV, network, audit-export or lifecycle mutation adapters. |
| Three more pages retained private evidence/drafts during estate/user changes, ignored tab resumption, or accepted detached completions. Same-turn duplicate forms escaped React busy state. | Shared private-scope watcher/remount plus synchronous generation and request locks for Operator Decisions, Launch Readiness and Evidence. These are display/request fences, not server authorization. |
| Export response/body completion could release old-context bytes after a browser scope change. | Abort and check scope before fetch, after response and after blob creation; cancel on unmount; release object URLs in finally. |
| An interrupted Launch write remained busy without a deadline. | Reproduced with an abort-aware pending transport; add a 20-second deadline and reconciliation warning, never automatic resend. A deadline does not prove the server stopped. |

## Connected supported-source journey: actual API + parser + PostgreSQL

The new native tests sign in through the real password/session API. Synthetic
users, estate memberships, source roots, grants and policies are initial fixture
provisioning, not customer identities or independent-human review. Queue delivery,
control-plane probes and parser launcher isolation are doubles; `JobExecutor` and
the source parser/pipeline execute against real temporary source files and SQL.
No seeded scan, task, proof or manual SQL repair supplies a successful journey.

1. Failed password is refused; authorized current sessions select their exact estate.
   A foreign-estate submission returns 404 and a readonly submission 403.
2. Submit supported source work, execute it, inspect the real MD5 finding and
   immutable scan output. Delivering the same descriptor again does not recollect.
3. Scan and record **integrity PASS** coexist with original **compliance FAIL**.
   JSON export retains the original MD5/compliance observation; it does not silently
   replace it with later remediation state.
4. Create the existing task/accountable owner and SOURCE_SITE change. The analyst
   cannot approve. A separately authenticated admin/reviewer approves once;
   duplicate approval returns 409. These are distinct synthetic identities, not
   evidence of two actual people or organizational independence.
5. Report owner completion. Operator output says `reported_complete=true` but
   `current_condition_verified=false` until independent verification.
6. Change the actual source, submit a second supported job, run the parser and
   compare the exact original site. SHA-256 produces VERIFIED/current=true;
   SHA-384 produces INCONCLUSIVE/current=false for the SHA-256 requirement.
7. Read the retained proof revision through the API and the operator interpretation.
   Another estate cannot read its history. Successfully settled work releases its
   budget through normal execution; UNKNOWN exercises retain reservations.

### Adverse-state coverage and interpretation

| Dimension | Executed evidence / limitation |
|---|---|
| Denied, foreign, residency, private NULL owner | Native source and read-boundary cases, with and without optional tenant middleware; selected auth/estate suites. No NULL-as-global fallback. |
| Stale, expiry, revocation, malformed/corrupt authority, partial/failed observations | Existing selected assurance/execution/parser/retraction suites rerun in the 507-case API selection; browser resume/old-response cases in the 53 new regressions. Not every adverse state is combined into one browser-to-backend journey. |
| Approval/revision contention | Native competing writers and approvals, one winner/one conflict. |
| Concurrent evidence withdrawal | Four native transactions block behind proof membership locks; later current interpretation is withdrawn. Existing API retraction regressions remain in the selected run. |
| Interrupted/duplicate delivery and unknown effects | Native claim/rollback/UNKNOWN/reconciliation/restore, plus selected process-recovery tests. No success inferred from timeout, ACK, owner completion or an interrupted response. |
| Browser/API/export agreement | Native API and JSON preserve original observations and separate owner report/proof; built browser uses synthetic HTTP to exercise interpretation/privacy. **Not** one real browser connected to the PostgreSQL backend. |

The scope is the supported source workflow, not complete SBOM/CBOM/NBOM/TechBOM/
HBOM/VBOM qualification. All six keep their existing acquisition, identity,
freshness and estate requirements; no family-wide or whole-bank coverage claim.

## Final executed results

| Run | Final result | Boundary |
|---|---|---|
| Actual PostgreSQL 16.14, matching native dump/restore clients | **16 passed**, 17 warnings, 45.41 s | No skipped tests in this native selection. Separate disposable databases, bounded races and logical recovery. |
| Selected API/security: exact 31 files retained in JSON | **507 passed**, 9 warnings, 245.82 s | Selected contracts, not the entire repository. Includes 12 new exact-algorithm cases. |
| Entire frontend: 48 files | **480 passed**, 129.52 s | Includes all **53** new regressions, not additive. DOM/mock transport. 20 React act warnings remain: four in the new synchronous fence tests, 16 in existing tests. |
| Built console in Chromium 153.0.8010.0 | **9 passed**, zero captured page errors | Real browser engine, intercepted synthetic HTTP; not live-backend/site acceptance. |
| Database/shared/remediation/selected worker libraries | **929 passed, 1 skipped, 8 deselected**, 147 warnings, 71.84 s | The old pg_virtualenv-only runtime-gate test remains skipped, not passed. Its intent is separately exercised by the new native runtime-gate case, not a relabeling of that skip. Eight `live` cases remain deselected by this default selection. |
| Frontend typecheck / production build / toolchain | Pass / pass (1.20 s) / **7 passed**, no skips | No browser matrix or image publication inferred. |
| Ruff (`services scripts shared`), environment `pip check`, Node script syntax, whitespace | Pass | Local configured checks, not CI. |
| Documentation/input validation | **407 Markdown files / 2,000 local links / 58 anchors**, zero errors; 14 changed shell blocks syntax-checked; 126 retained hashes match | Local file/anchor, shell syntax and current source/build/log fingerprint checks; no external-link fetch or older evidence relabeling. |

Counts overlap across selections and reruns: do not sum them as unique coverage.
Python environment: 3.11.2; SQLAlchemy 2.0.52; Alembic 1.19.1; pytest 9.1.1;
psycopg2-binary 2.9.12; FastAPI 0.141.1. Node 22.22.3. These are the actual
external qualification environment, not an assertion about every CI/image lock.

## Diagnostic history, not hidden failures

- The corrected final 53-case browser regression set against the five original
  application files produced **48 failures / 5 passes**. A finally restored all
  five corrected files byte-for-byte. Earlier 52-case and invalid-selector runs
  are superseded, not counted as additional failures fixed.
- The new Launch deadline test failed before its timer correction; a first
  wrong-directory append executed no matching test and is not red evidence.
- The first selected API run had 502 passes / 5 failures: three subprocess tests
  exposed an external bootstrap PYTHONPATH omission; two legacy fake-auth tests
  needed the trusted tenant-context fixture, including explicit platform visibility
  for NULL-owned private history. The corrected final selection is recorded above.
- A broader library run had 928 passes / 1 failure / 1 skip: the new downgrade
  guard unnecessarily affected SQLite, whose old schema already retained UNKNOWN.
  Scope that guard to PostgreSQL; the unchanged index-only SQLite round-trip now
  preserves its unsettled job/history and passes. Native guarded downgrade still
  refuses UNKNOWN and is rerun, not inferred from SQLite.
- Warnings remain visible: Alembic path_separator, Pydantic deprecations, existing
  library warnings and React act diagnostics. No claim of warning-free tooling.

## Reproduction and retained evidence

Frontend: `npm --prefix frontend test`, `npm --prefix frontend run typecheck`,
`npm --prefix frontend run build`, `npm --prefix frontend run test:toolchain`.
Native database opt-in and bootstrap are in the PostgreSQL record; browser tool
installation/invocation is in the browser record. JSON retains exact API selection,
PG case names/results, browser checks, run-file hashes and publication-source hashes.
Raw local logs/XML are `/home/user/quality-ninth-{api,pg,frontend,library}-final.*`,
`quality-ninth-frontend-final-red.*`, `quality-ninth-browser-final.{json,err}` and
`quality-ninth-{typecheck,build,toolchain}-final.log`. They are external workspace
execution records, not committed customer data or exported production logs.

## Release and remaining acceptance

Use a coordinated reviewed API/worker/parser/frontend release, normal migration
account and isolated restore procedure. 0106 is additive; PostgreSQL rollback
refuses while UNKNOWN jobs remain, retaining their reservations. Never relabel
uncertainty or free budget to force a downgrade. See the database record/runbook.

Still outstanding: different-human review; real browser-to-deployment journey;
intended bank workstation/browser/SSO/TLS/proxy and accessibility matrix; real
Docker/Redis/ingress/daemon fault exercises; broader six-BOM identity/staleness
matrix; PostgreSQL/Redis TLS and deployment-version matrix; HA/WAL/PITR, encrypted
DB-plus-evidence backup/cutover; measured capacity/soak and actual RPO/RTO; actual
operating owners, assessment and independent technical/customer acceptance.
No readiness gate or historical generated verdict was manually promoted. No SLA,
24/7 staffing, uptime, registry digest, CI pass, merge or site update is implied.
Publication uses `[skip ci]` per standing instruction; the user-owned unidentified
CI failure remains unclaimed and unchanged.
