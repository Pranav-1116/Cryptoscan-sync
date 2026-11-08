# Bank questionnaire execution records and reproduction

**2026-10-23 UTC.** Baseline PR head
`5a686ed2e4f38db29b1dd449984dafb0dab43d91`; containing publication and source
hashes bind this pass. All inputs/identities are local synthetic fixtures.
No live bank, HSM/cloud probe, native database or network scan was authorized or
run in this pass. Earlier native/browser/recovery evidence is historical.

## Records

- `boundaries-initial-red.log`:39 new adverse cases,37failed/2passed before fixes.
- `boundaries-second-red.log`:44 cases,4failed/40passed after initial fixes.
- `boundaries-third-red.log`:51 cases,5failed/46passed before final risk/cohort fixes.
- `banking-ui-red.log`:6 failures against the original existing banking view.
- `banking-ui-green.log`:same6 cases pass after the view fixes.
- `regression.log` / `regression.xml`:648 passing selected Python cases,4 warnings,
  zero failures/errors/skips.
- `six-bom.log` / `six-bom.xml`:21 separate current six-BOM adverse cases pass,
 4 warnings, zero failures/errors/skips.
- `frontend.log` / `frontend.xml`:548 passing cases/52 files,20 known act warnings,
  zero failures/errors/skips.
- `typecheck.log` / `build.log`:successful source toolchain checks.
- `register-review.json`:all57 questions/source references present and hashed,
  but bank acceptance is BLOCKED.
- `strict-review.json`:same honest blocker report; expected process exit1, not an
  invalid-register error or a passing bank qualification.

ANSI formatting and trailing whitespace have been removed from retained text
logs. Fixtures include explicit synthetic names/canaries, not bank data. No
private keys, installed dependencies, compiled output or binaries are committed.

## Environment

Python3.11; external virtualenv installed from `requirements.txt` constrained by
`requirements.lock.txt`; pytest9.1.1, SQLAlchemy2.0.52, Pydantic2.13.5,
FastAPI0.141.1. SQLite fixtures only for API persistence. Node22.22.3/npm10.9.8,
frontend dependencies from lockfile via `npm ci --ignore-scripts`.
No product dependency or lockfile was changed by this pass.

The648-case suite covers all CBOM tests, quantum tests, shared algorithm registry
and classifier, banking/ISO20022/KMIP/dependency-security APIs, quantum API,
agility history/roadmaps, worker quantum projection and the new boundary/register
contracts. It does not claim all repository tests or real integrations pass.

Warnings are disclosed, not suppressed: existing auth Pydantic Config deprecation,
network/cloud `register` field-name shadowing, TestClient/httpx deprecation.
Frontend20 act warnings remain in CriticalScope/Tenancy. No test-isolation or
warning-policy weakening was applied to get a green total.

## Reproduction

From the repository root in an approved constrained Python environment. The
existing monorepo runner sets service/shared import paths before pytest. These
commands do not start services or access a production deployment:

```bash
RUNNER=docs/readiness-evidence/quality-usability-release-operations-2026-10-23/run-tests.py
python "$RUNNER" \
  services/api/tests/unit/test_bank_vendor_questionnaire_boundaries.py \
  services/api/tests/unit/test_bank_vendor_questionnaire_register.py \
  services/cbom/tests services/quantum/tests \
  services/api/tests/unit/test_banking_endpoints.py \
  services/api/tests/unit/test_banking_iso20022_kmip.py \
  services/api/tests/unit/test_bank_dependency_security.py \
  services/api/tests/unit/test_quantum_plan.py \
  services/api/tests/unit/test_agility_history_simulate_pqc.py \
  services/api/tests/unit/test_agility_roadmap_trend.py \
  services/worker/tests/unit/test_quantum_stage.py \
  shared/shared_models/tests/test_quantum_classify.py \
  shared/shared_models/tests/test_algorithm_registry.py -q

npm --prefix frontend run typecheck
npm --prefix frontend run build
npm --prefix frontend test -- --reporter=default

# Integrity-only review: exit0 is not bank acceptance.
python scripts/bank_vendor_questionnaire.py
# Expected exit1; invalid data/path/schema must exit2 instead.
if python scripts/bank_vendor_questionnaire.py --strict; then
  echo 'Unexpected qualification: investigate before proceeding' >&2
  exit 1
else
  result=$?
  test "$result" -eq 1
fi
```

Use external output paths for JUnit/log reproduction. Do not overwrite retained
records and their manifest to make a rerun appear identical. Historical negative
runs are expected to pass on fixed source; do not restore source in place or
weaken the adverse assertions just to reproduce a total.

[Detailed report and acceptance limits](../bank-vendor-questionnaire-2026-10-23.md).
