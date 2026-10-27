# Developer checks

For active CI definitions, matrix coverage, dependency constraints and evidence
limitations, see [Release automation](release-automation.md). Copies in
`github-workflows/` are historical proposals; `.github/workflows/` is authoritative.

For supported frontend engines, frozen installs, Vite/Rolldown compatibility and
all-dependency advisory/coverage checks, see
[Frontend toolchain hardening](frontend-toolchain-security.md). A zero npm audit
is a dated dependency observation, not production security approval.


For the production static source-parser policy, digest/runtime/staging
prerequisites and deliberately unqualified Docker boundary, see
[Scanner isolation](scanner-isolation.md). The stock Compose worker is not a
provisioned isolated-parser deployment and fails closed in production until
those prerequisites are supplied.

For durable per-destination receipts, retry/claim semantics, exact tenant
routing and the migration/legacy-history boundary, see
[Notification delivery](notification-delivery.md). For separately enabled,
explicitly scoped automatic retries see
[Notification scheduler](notification-scheduler.md). SMTP remains unimplemented
in this notification path; deployment/provider qualification remains open. For
metadata-only backlog counts and paginated receipt history without triggering a
send, see [Read-only receipt inspection](notification-inspection.md).

## Running the Python suites from a bare checkout (no Docker)

```
python3 -m venv .venv
.venv/bin/pip install pydantic pydantic-settings pyyaml cryptography pytest pytest-asyncio pytest-timeout \
    gitpython click structlog sqlalchemy fastapi httpx uvicorn python-multipart fpdf2 redis fakeredis \
    python-jose passlib bcrypt pyjwt email-validator jinja2
export PYTHONPATH="$(for d in shared/*/ services/*/; do printf '%s%s:' "$PWD/" "$d"; done)"
(cd services/scanner && ../../.venv/bin/python -m pytest tests -q)        # ~2 s
(cd services/worker  && ../../.venv/bin/python -m pytest tests/unit -q)   # ~15 s, sqlite + fakeredis
(cd services/api     && ../../.venv/bin/python -m pytest tests/unit -q)   # slow (>20 min); use -k to scope
.venv/bin/python scripts/accuracy_benchmark.py                             # ground-truth corpus, ~2 s
```
`PYTHONPATH` must include *every* `services/*` and `shared/*` directory (the `Makefile` does the same); a partial path shows up as `ModuleNotFoundError: cloud_scanner.estate` / `payment_crypto.connectors` rather than as a real failure.
