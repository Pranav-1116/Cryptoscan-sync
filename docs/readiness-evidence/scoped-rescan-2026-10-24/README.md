# Replay scoped rescan checks

Use a reviewed constrained Python 3.11 environment and repository dependency
locks. Text artifacts strip terminal colour/trailing whitespace; JSON/XML/image
artifacts are copied unchanged. No credentials, source snapshots or raw findings
are retained here.

```bash
bash docs/readiness-evidence/production-data-path-2026-10-24/run-python-tests.sh \
  services/api/tests/unit/test_cbom_legacy_reconciliation.py \
  services/api/tests/unit/test_cbom_controlled_history.py \
  services/api/tests/unit/test_cbom_rescan_inspection.py \
  services/database/tests/unit/test_import_provenance.py \
  services/database/tests/unit/test_audit_chain_incremental.py \
  services/api/tests/unit/test_assurance_workflows.py \
  services/api/tests/unit/test_backup_encryption.py services/evidence/tests \
  services/scanner/tests/unit/test_file_observation_receipts.py \
  scripts/tests/test_capacity_verdict.py --junitxml=/external/python.xml
npm --prefix frontend test -- --maxWorkers=2
npm --prefix frontend run typecheck
npm --prefix frontend run build
```

Use the [existing disposable fixture setup](../controlled-history-2026-10-24/README.md),
not customer data. With absolute package paths and API/database unit-test folders
on PYTHONPATH, set `CRYPTOSCAN_PROVENANCE_TEST_DATABASE_URL` to an owned local
`cryptoscan_e2e_*` DB. Each PG fixture creates/drops its own random database:

```bash
python -m pytest services/api/tests/unit/test_cbom_rescan_postgres.py \
  services/api/tests/unit/test_cbom_controlled_postgres.py -m '' -q
```

For the browser, run the existing fixture harness first against the migrated
owned API/console and external private principal config; then run the inspection
harness. These runs perform three and two normal logins respectively. Respect
normal login/rate-limit windows; never disable the limiter for the replay.

```bash
python scripts/controlled_cbom_e2e.py --config /external/private.json \
  --chromium /approved/chromium --report /external/history.json
python scripts/rescan_cbom_e2e.py --config /external/private.json \
  --history-report /external/history.json --chromium /approved/chromium \
  --report /external/browser.json --screenshot /external/browser.png
```

The harness is intentionally local/synthetic-only. It creates/removes actual
source files, scans them, hashes/loads real evidence, provisions a test job/system
envelope and exercises the browser. It does **not** dispatch the worker or
qualify production isolation/admission. It injects/restores a synthetic payload
tamper and verifies continued grade refusal; do not run it against deployments.
Remove owned PostgreSQL/runtime/private-config data after retaining results.
