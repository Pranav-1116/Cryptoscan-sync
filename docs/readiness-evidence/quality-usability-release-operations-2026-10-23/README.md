# Retained execution records and reproduction — steps 7–10

**2026-10-23 UTC.** Synthetic sandbox evidence, not release/site/user approval.
The containing Git commit is the publication binding; exact current source and
record digests are in the [results manifest](../quality-usability-release-operations-results-2026-10-23.json).

## Records

- `ui-red.log`: original8 Launch cases,7 failed/1 passed.
- `timeout-red.log`, `repeat-focus-red.log`: additional targeted adverse failures.
- `locale-red.log`: missing existing language control,1 failed/15 name-filter exclusions.
- `browser-reflow-red.json`: real320CSS-pixel clipping failure.
- `operations-red.log`: clock rollback,1 failed/1 passed.
- `release-red.log`: four adverse package-binding failures.
- `frontend.log` / `frontend.xml`: final542 passing tests,51 files,20 retained act warnings.
- `typecheck.log` / `build.log`: current local source toolchain checks.
- `browser.json`:15 built-console Chromium checks PASS, no page errors.
- `backend.log` / `backend.xml`:92 selected API/operations/release tests,5 warnings.
- `regression.log` / `regression.xml`:248 broader regressions,4 warnings.
- `native.log` / `native.xml`:19 actual native PostgreSQL cases,23 warnings.
- `native-harness-failure.log`: prior17 pass/2 missing-output-path harness failures.
  Its environment repr is omitted; it is not product-failure evidence.
- `trace.json`, `cohort.json`: current native rerun's raw matched trace and tiny
  synthetic SQL/files/key recovery/failback observations, still not site claims.
- `cleanup.json`: zero fixture DBs before clean server shutdown.
- `run-tests.py`: the constrained-environment bootstrap used for pytest,
  relocated to compute the repo root rather than hardcode this sandbox path.

Text logs have ANSI styling stripped. The omission in the failed harness log is
explicit. No database/archive, generated key, dependency tree, compiled browser,
source tarball or production customer data is included.

## Environment used

Linux disposable sandbox; Node22.22.3/npm10.9.8; Python3.11 with constrained
requirements; pytest9.1.1, SQLAlchemy2.0.52, psycopg2-binary2.9.12,
Pydantic2.13.5, FastAPI0.141.1, cryptography50.0.1 and PyYAML6.0.3.
Native PostgreSQL16.2 supplied through external `pgserver`0.1.4, private Unix
socket, local trust and UTF8 scratch databases. This is **not current PostgreSQL
patch, production authentication, HA or TLS qualification**.

External browser harness: playwright-core1.64.1, `@sparticuz/chromium`153.0.0,
actual browser153.0.8010.0. Runtime library path contains the externally prepared
Chromium dependencies, including libnspr4. Tools are not product dependencies or
vendored here. The browser intercepts HTTP at a synthetic origin and refuses
external requests; it needs the locally built frontend, not a running bank API.

## Reproduce in an equivalent authorized test environment

Run from the repository root with the constrained Python environment activated
and frontend dependencies already installed from the lockfile. This record does
not install or approve a fresh toolchain. Use your approved environment paths.
`run-tests.py` bootstraps the monorepo service/shared imports and then invokes
pytest; it does not skip failures or turn on a production override.

```bash
RECORDS=docs/readiness-evidence/quality-usability-release-operations-2026-10-23
npm --prefix frontend run typecheck
npm --prefix frontend test -- --reporter=default
npm --prefix frontend run build

# Equivalent external browser runtime required; these were the sandbox paths.
LD_LIBRARY_PATH=/home/user/quality-browser-tools/runtime-libs/lib \
CRYPTOSCAN_BROWSER_TOOLS=/home/user/quality-browser-tools/node_modules \
node frontend/scripts/critical-browser.mjs

python "$RECORDS/run-tests.py" \
  services/api/tests/security/test_operator_release.py \
  services/api/tests/security/test_release_attestation.py \
  services/api/tests/security/test_release_check_images.py \
  services/api/tests/security/test_release_image_pinning.py \
  services/api/tests/security/test_operational_policy_gate.py \
  services/api/tests/security/test_operational_deployment_readiness.py \
  services/api/tests/unit/test_launch_readiness.py \
  services/api/tests/unit/test_operating_current_window.py -q

python "$RECORDS/run-tests.py" \
  services/api/tests/unit/test_{assurance*,relationship*,package*,ssh*,remediation*,execution*}.py \
  services/api/tests/unit/test_six_bom_current_evidence.py \
  services/api/tests/unit/test_backup_encryption.py -q
```

For native tests, first provision a **new disposable local** PostgreSQL cluster
with private Unix socket and UTF8/template0 support, as an unprivileged test
user. Never substitute an existing deployment. The fixture creates/drops uniquely
named scratch databases and fences/terminates its own synthetic connections.
`disposable-local-only` is explicit authorization, not a dry-run flag.
The following exports record the actual sandbox inputs, whose server has now
been stopped; create an equivalent fresh lab before rerunning. Keep output paths
external, writable and disjoint from the checkout. Do not run concurrent load
jobs when interpreting performance measurements.

```bash
RECORDS=docs/readiness-evidence/quality-usability-release-operations-2026-10-23
export CRYPTOSCAN_QUALITY_PG_BIN=/home/user/quality-venv/lib/python3.11/site-packages/pgserver/pginstall/bin
export PATH="$CRYPTOSCAN_QUALITY_PG_BIN:$PATH"
export CRYPTOSCAN_QUALITY_PG_OPT_IN=disposable-local-only
export CRYPTOSCAN_QUALITY_PG_URL='postgresql+psycopg2://user@/postgres?host=/home/user/quality-full-pg-socket&port=55439'
export CRYPTOSCAN_MEASURE_OUT=/home/user/quality-twelve-trace-rerun.json
export CRYPTOSCAN_COHORT_OUT=/home/user/quality-twelve-cohort-rerun.json
python "$RECORDS/run-tests.py" \
  services/api/tests/unit/test_workflow_postgres.py \
  services/api/tests/unit/test_restore_failure_postgres.py \
  services/api/tests/unit/test_trace_workload_postgres.py \
  services/api/tests/unit/test_isolated_cohort_recovery.py -m live -q
```

Both output variables are required. Omitting them caused the preserved harness
failure after expensive test work; do not repeat that invocation or call it a
product regression. Without native opt-in the existing live fixtures explicitly
skip and are **not qualification**. Final retained native JUnit has no skips.

To regenerate JUnit use `--junitxml` for pytest, and Vitest's additional
`--reporter=junit --outputFile` flags, always writing outside the checkout.
Retained negative logs are historical adverse runs; rerunning their assertions
against current fixed source is expected to pass. Do not weaken an assertion,
replace source in-place or silently hide warnings to reproduce the totals.
