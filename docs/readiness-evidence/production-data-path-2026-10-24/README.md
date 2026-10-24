# Retained data-path execution and replay

These are synthetic sandbox engineering records, not customer evidence or production approval. See the [execution narrative](../production-data-path-2026-10-24.md), [implementation limits](../../operations/production-data-path-hardening.md) and [upgrade/rollback runbook](../../runbooks/cbom-0107-upgrade.md).

`python.xml`/`frontend.xml`/`postgres.xml` are final JUnit records. Corresponding `.txt` files retain warnings; only trailing whitespace/blank EOF lines are normalized in text transcripts. JUnit/JSON contents are not rewritten. Browser JSON lists actual assertions, receipts and HTTP outcomes, without passwords/session cookies. `restart-database.json` records a changed real postmaster timestamp and refused connections while stopped. The screenshot is from the real built console with synthetic users/data; its “PRODUCTION” dropdown is an estate filter, not production runtime activation. Earlier red tests are retained with their fixture corrections explained in the narrative.

## Regression replay

Use Python 3.11 and the constrained root dependencies; the run used `/home/user/bank45-venv/bin/python`. `rfc3986-validator==0.1.1` is now a required locked runtime dependency, not an optional schema-checking extra. Test-helper tools do not belong in production requirements.

From repository root, write outputs **outside** retained records:

```bash
bash docs/readiness-evidence/production-data-path-2026-10-24/run-python-tests.sh --junitxml=/external/python.xml
npm --prefix frontend run typecheck
npm --prefix frontend run build
npm --prefix frontend test -- --reporter=default --reporter=junit --outputFile=/external/frontend.xml
python scripts/bank_vendor_questionnaire.py
if python scripts/bank_vendor_questionnaire.py --strict; then
  echo 'Unexpected acceptance closure; investigate' >&2
  exit 1
else
  result=$?
  test "$result" -eq 1
fi
```

**Live migration test warning:** `test_migration_chain_postgres.py` drops/recreates the database named by `CRYPTOSCAN_TEST_PG_URL`. Set that variable to an authorized dedicated disposable database, **never an existing deployment or the `postgres` administration database**. Ensure the role can create/drop only authorized test databases. The application E2E database must be different from this resettable migration-test database.

```bash
: "${CRYPTOSCAN_TEST_PG_URL:?set the dedicated disposable migration-test URL}"
python docs/readiness-evidence/quality-usability-release-operations-2026-10-23/run-tests.py \
  services/database/tests/unit/test_migration_chain_postgres.py -m live -q \
  --junitxml=/external/postgres.xml
```

Require actual tests to run; a skip is not PostgreSQL parity evidence. The retained run has ten passes and no skips.

## Actual browser/API/PostgreSQL replay prerequisites

`scripts/production_cbom_e2e.py` is an opt-in check, **not a database provisioner or production activation tool**. It never drops a database. It imports synthetic declarations and leaves those owned test rows for inspection. You must supply:

1. A separate authorized disposable PostgreSQL database named `cryptoscan_e2e_...`, migrated from base to 0107. Do not use metadata bootstrap.
2. Full API application and a **built** `frontend/` console, with `/api` proxying to the same API. Use the normal stack tooling or separate managed processes. The recorded sandbox used API `0.0.0.0:8010`, Vite preview `0.0.0.0:3003`, explicit host allowlists, relative browser requests and development API settings. It did not disable production checks under `ENVIRONMENT=production` or demonstrate activated production admission.
3. Three synthetic durable users with a common randomly generated test password: `e2e_bank_a` / security analyst / tenant `e2e-a`, `e2e_bank_b` / security analyst / tenant `e2e-b`, and `e2e_reader` / readonly / tenant `e2e-a`. These IDs are part of this test fixture only, not real bank identities.
4. An external private JSON config with `database_url` and `password` (optionally `username_a`, `username_b`, `username_reader`), and an external private storage-state output. **Never commit either.** Browser state contains authentication cookies.
5. Optional Playwright tooling and a compatible Chromium executable. The recorded sandbox used Playwright 1.64.1 and Chromium from external `@sparticuz/chromium 153.0.0`; required Linux libraries were extracted from that package's `al2023.tar.br` and exposed with `LD_LIBRARY_PATH=/tmp/al2023/lib`. The browser was headless/no-sandbox **inside the disposable sandbox only**; this is not browser/container isolation qualification. A normal approved local Chromium is preferable for independent reproduction.

For an **empty, already migrated, authorized disposable application database**, this provisioning example mirrors the executed synthetic fixture. Configure external `DATABASE_URL`, an external `CBOM_E2E_CONFIG` destination, and the repository's Python import environment first. It refuses non-test names, a non-empty estate or overwriting a config file. Do not enable shell tracing around credentials.

```python
import json, os, secrets
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from api.security.passwords import hash_password
from db.models.system import System
from db.models.tenant import Tenant, TenantMembership
from db.models.user import User
from db.repositories.user_repository import UserRepository

url = os.environ["DATABASE_URL"]
assert make_url(url).get_backend_name() == "postgresql"
assert (make_url(url).database or "").startswith("cryptoscan_e2e_")
password = secrets.token_urlsafe(24)
with Session(create_engine(url)) as db:
    assert db.query(User).count() == db.query(Tenant).count() == db.query(System).count() == 0
    repo = UserRepository(db)
    for username, roles, tenant in [
        ("e2e_bank_a", ["security_analyst"], "e2e-a"),
        ("e2e_bank_b", ["security_analyst"], "e2e-b"),
        ("e2e_reader", ["readonly"], "e2e-a"),
    ]:
        repo.create_user(username, hash_password(password), roles)
        if not db.get(Tenant, tenant):
            db.add(Tenant(id=tenant, name="Synthetic " + tenant, slug=tenant))
        db.add(TenantMembership(tenant_id=tenant, username=username, tenant_role="member"))
    db.commit()
fd = os.open(os.environ["CBOM_E2E_CONFIG"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as output:
    json.dump({"database_url": url, "password": password}, output)
```

Start the reviewed API with its intended **sandbox** environment and independently generated application secret; do not use these test users/settings for a production rollout. Build the frontend, then serve the build with its configured proxy. Servers must be fully started before the following checks; no API responses are mocked by the script.

```bash
: "${CBOM_E2E_CONFIG:?set an external private config path}"
: "${CBOM_E2E_CHROMIUM:?set an approved local Chromium executable}"
python scripts/production_cbom_e2e.py \
  --config "$CBOM_E2E_CONFIG" --chromium "$CBOM_E2E_CHROMIUM" \
  --base-url http://127.0.0.1:3003 \
  --report /external/browser.json --storage-state /external/browser-private-state.json
```

For the controlled durability check, stop API and then PostgreSQL **through the owning process/service manager**. Verify connections are refused, restart PostgreSQL with the **same data directory**, then restart API with the **same application secret/database**. Keep the frontend build unchanged. Record changed `pg_postmaster_start_time()` and owned row counts separately. This is not `kill -9`, backup restore or HA/failover. Reuse the private cookie state, without logging in again:

```bash
python scripts/production_cbom_e2e.py \
  --config "$CBOM_E2E_CONFIG" --chromium "$CBOM_E2E_CHROMIUM" \
  --base-url http://127.0.0.1:3003 \
  --readback-only /external/browser.json --report /external/restart-browser.json \
  --storage-state /external/browser-private-state.json
```

After review, stop all owned sandbox services and remove the owned disposable databases/data directories and private credentials/browser state. Do not delete any existing deployment, repository or unrelated test data. Production qualification, external evidence, original-45 gaps and the 57-item blocked acceptance register are unchanged by a passing replay.
