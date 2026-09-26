
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
