# Historical CBOM execution artifacts

These records support the [execution narrative](../historical-cbom-2026-10-24.md),
not a whole-product production or bank verdict. The [manifest](../historical-cbom-results-2026-10-24.json)
hashes changed source and retained artifacts. JSON/XML/images are copied unchanged;
text transcripts have terminal colour escapes, trailing whitespace and blank lines at EOF removed.

## Replay

Use a reviewed constrained Python 3.11 environment with the repository locked
dependencies and Node satisfying `frontend/package.json`. From repository root:

```bash
bash docs/readiness-evidence/production-data-path-2026-10-24/run-python-tests.sh \
  services/api/tests/unit/test_cbom_legacy_reconciliation.py \
  services/database/tests/unit/test_import_provenance.py \
  services/database/tests/unit/test_audit_chain_incremental.py \
  --junitxml=/external/historical-python.xml
npm --prefix frontend ci --no-audit --no-fund
npm --prefix frontend test
npm --prefix frontend run typecheck
npm --prefix frontend run build
```

For the opt-in real PostgreSQL suite, provision **owned disposable local** databases,
not a deployment. Give `CRYPTOSCAN_PROVENANCE_TEST_DATABASE_URL` a
`cryptoscan_e2e_*` application database migrated to 0107 and
`CRYPTOSCAN_TEST_PG_URL` the separately owned **cryptoscan_migration_test** database.
The latter test suite drops/resets its public schema. The audit fixture creates
and drops its own random `cryptoscan_e2e_audit_*` databases; its role needs that
scratch-only privilege. The application's production role does not need CREATEDB.
Set **absolute** package paths in PYTHONPATH, because migration subprocesses change
working directory, and include `services/database/tests/unit` for the shared case module.

```bash
: "${CRYPTOSCAN_PROVENANCE_TEST_DATABASE_URL:?set an owned disposable local database}"
: "${CRYPTOSCAN_TEST_PG_URL:?set only the owned cryptoscan_migration_test database}"
python -m pytest services/database/tests/unit/test_provenance_postgres.py \
  services/database/tests/unit/test_migration_chain_postgres.py \
  -m '' -q --junitxml=/external/historical-postgres.xml
```

The `-m ''` intentionally includes the ten migration tests marked live; default
repository test selection excludes them. Do not count deselected/skipped tests
as PostgreSQL execution.

For browser replay, follow the [existing disposable fixture setup](../production-data-path-2026-10-24/README.md):
actual migrated app, three synthetic tenant principals, private external config,
compiled console/proxy, approved local Chromium. The new harness seeds only
synthetic historical rows in a local `cryptoscan_e2e_*` database and uses actual
password login/upload/review/export. It does not mock the API.

```bash
: "${CBOM_E2E_CONFIG:?external private synthetic-principal config}"
: "${CBOM_E2E_CHROMIUM:?approved local Chromium path}"
python scripts/legacy_cbom_e2e.py \
  --config "$CBOM_E2E_CONFIG" --chromium "$CBOM_E2E_CHROMIUM" \
  --base-url http://127.0.0.1:3003 \
  --report /external/historical-browser.json \
  --screenshot /external/historical-browser.png
```

Run the existing `scripts/production_cbom_e2e.py` separately as described in its
fixture README. Each harness performs three logins; respect the normal five-login/
minute/IP limit. The recorded run used separate **owned sandbox API process
sessions**, without disabling or modifying security controls. Credentials and any
saved session state must stay external, private and out of Git.

After replay, stop owned API/console/PostgreSQL processes, verify stopped state,
remove only their owned data/credentials/session states and record cleanup. Do
not modify or remove customer deployments or unrelated workspace files.

## Artifact meanings

- `python.*`: selected regression run, not all repository tests.
- `frontend.*`: complete frontend test run; existing warnings disclosed.
- `postgres.*`: explicit 27-check actual PG run, including the unlocked negative
  control and fixed serialization tests in isolated scratch audit databases.
- `browser.*`: 17-check historical flow, actual application audit verification and screenshot.
- `existing-browser.*`: 16-check existing import/export/concurrency regression.
- `typecheck.txt`, `build.txt`, `quality.txt`: local compiler/lint/dependency checks.
- `cleanup.json`: owned resources stopped/private state removed.

No new recovery, capacity, provider interoperability, CI/image, independent security,
accessibility/Arabic, bank or commercial/staffing acceptance is implied.
