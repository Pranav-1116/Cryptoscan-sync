# Dependency Vulnerability Audit — 2026-08-30

Tool: `pip-audit` (PyPI advisory DB, queries live OSV) over `requirements.txt`.

## Result

**No known vulnerabilities found** in the pinned production dependency set.

Command (re-run before every release):

```bash
python -m pip_audit -r requirements.txt
```

## Scope & honest limits

- Audited the dependency *names and versions resolved from requirements.txt*
  — the editable first-party packages (api, worker, database, payment_crypto,
  shared/*) are not in the PyPI advisory DB and are covered by the repo's own
  test gate instead.
- The advisory DB changes daily; a clean report today is not a clean report
  tomorrow. CI should run `pip-audit` on every push (see
  `docs/dev/github-workflows/ci.yml`, parked there until a token with
  `workflows` permission installs it).
- Not covered: base images (`python:3.11-slim`, `postgres:16-alpine`,
  `nginx:1.27-alpine`) — scan with `trivy` in the pipeline before promoting.
