# Local readiness witness — Linux software increment, 2026-10-25 UTC

**Decision:** publish a bounded Phase 2 implementation increment for review. Phase 2 is not complete or production-qualified; no bank host was collected and no external qualification was fabricated.

## Implemented boundary

- Hardened literal Debian package metadata parsing with conservative refusal of ambiguous duplicate/multiarch identity, preservation of held/pending-removal installed records and unknown versions.
- Typed deterministic `cryptoscan.linux-software-inventory/v1` over the original verified intake and exact historical approved target; no new collection.
- Read-only scoped API plus explicit Linux software read in the existing coverage drilldown. Separate package records, binary presence and mapped paths. No new service/table/dashboard.
- Original observations/provenance and package input failures retained. Architecture/license/dependency/runtime/crypto-use unknown; no invented purl or artifact digest. Not a standard CycloneDX SBOM.

## Completed local gates

Counts below overlap and **must not be summed**.

| Gate | Result | Scope / limitation |
|---|---|---|
| Selected Python regression | **1,103 passed, 3 skipped** | Inventory + shared-model suites and selected collection/foundation/coverage/host-evidence/worker API tests. Three genuine Windows-native skips. Not all API tests. This run preceded ten additional focused test cases below; product source was unchanged. |
| Final parser/software contracts | **40 passed** | Includes full registry/authorization/handoff/intake/completion; original evidence binding, tamper refusal, estate isolation, historical revocation reads, no second scan, unknowns, all three package-manager namespaces, self process-map separation and schema claim refusals. |
| Broader owned PostgreSQL | **60 passed** | Existing host-evidence, foundation and surface-coverage contracts plus first three Linux software database cases. Cleanup completed. |
| Final owned PostgreSQL | **30 passed** | Existing host-evidence + coverage + five final software cases, including APK/RPM namespace separation; owned disposable backend, cleanup completed. |
| Focused interface | **27 passed** | Existing coverage + new Linux software read, explicit GET, tenant/session headers, untrusted completeness/binding rejection, scope fences, 20-second timeout and ignored late response. |
| Full frontend | **660 passed** | Full local Vitest run with two workers. |
| TypeScript / production build | **PASS / PASS** | Local `tsc --noEmit` and Vite build; not production deployment. |
| Static/dependency/schema checks | **PASS** | Ruff on changed Python files; pip check; two model JSON Schemas pass Draft2020-12 schema checking. These are **not CycloneDX schema validation**. |
| Source-lock inclusion | **PASS** | Existing source-lock builder includes changed parser/host files and new shared model; no new release lock/signature or operator approval generated. |

The multiple-record unresolved-version test is an explicit synthetic typed-record witness, not a claim that duplicate Debian package names were admitted. The Debian parser refuses those records earlier. APK/RPM inputs are synthetic fixtures, not native Alpine/Red Hat qualification. Self-map tests read the sandbox process's approved procfs metadata and leave runtime/operation use UNKNOWN; they do not demonstrate bank application use. Fixture environment labels do not qualify production.

## Reproduction

From repository root with the existing validation virtual environment (optional `pgserver` is a validation dependency only):

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests shared/shared_models/tests \
  services/api/tests/unit/test_linux_software_inventory.py \
  services/api/tests/unit/test_collection_foundation.py \
  services/api/tests/unit/test_collection_surface_coverage.py \
  services/api/tests/unit/test_host_evidence.py services/api/tests/unit/test_host_worker.py -q
/home/user/qualify-venv/bin/pytest services/inventory/tests/test_dpkg_metadata.py \
  services/api/tests/unit/test_linux_software_inventory.py -q
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py \
  --acknowledge-local-synthetic --include-surface-coverage --include-linux-software \
  --junitxml=/home/user/linux-software-postgres.xml
(cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build)
```

The first run of the broader Python command omitted `scripts` from PYTHONPATH and stopped during test collection (`_bootstrap` missing). Correcting the command produced the completed 1,103-pass run. The first small direct pytest invocation also lacked service import paths; neither collection failure is represented as a passing run. No assertion or product behavior was weakened to fix these environment errors. Re-running the broad command now includes the subsequently added tests, so its count will differ from the retained historical output.

## Artifacts and integrity

[`linux-software-2026-10-25/manifest.json`](linux-software-2026-10-25/manifest.json) commits to the source/docs and 14 retained test/build/check artifacts in that directory. Text console artifacts have ANSI display escapes removed; JUnit XML is copied verbatim. These hashes support consistency/review, not authenticity, organizational approval or independent reviewer status.

## Remaining gates

Real named operator/reviewer returns and independently approved fresh release/source locks are pending. Existing assigned-human qualification controls remain in force. No credentials/private keys are requested, sent or stored. No workflow edits or CI execution are part of this increment; publication uses `[skip ci]`, which is a requested skip marker, not proof that every external workflow will honor it.

No claim of complete Linux/estate discovery, CycloneDX software compliance, all-six-BOM completeness, package health, artifact integrity, key use, traffic coverage, source/host authenticity, production rollout, 24/7 staffing or bank acceptance follows from these local tests. Next work remains the ordered Linux evidence/relationship and standard-projection acceptance gates in [guide 70](../bank-environment/70-linux-software-evidence-phase-two.md).
