"""Regenerate docs/api-reference/rest-api.md from the application OpenAPI schema (without starting a server).

Usage (repo root):
    PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')" \
    ENVIRONMENT=test SECRET_KEY=... .venv/bin/python scripts/gen_rest_api.py
"""
import collections
import os
import sys

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-abc123")
os.environ.setdefault("ALLOW_SQLITE", "true")

sys.path[:0] = [f"services/{d}" for d in sorted(os.listdir("services"))
                if os.path.isdir(f"services/{d}")]
if os.path.isdir("shared"):
    sys.path[:0] += [f"shared/{d}" for d in sorted(os.listdir("shared"))
                     if os.path.isdir(f"shared/{d}")]

from api.main import create_app  # noqa: E402

schema = create_app().openapi()
paths = schema["paths"]
METHOD_ORDER = {"get": 0, "post": 1, "put": 2, "patch": 3, "delete": 4,
                "head": 5, "options": 6}

groups = collections.defaultdict(list)
op_count = 0
for path, methods in paths.items():
    for method, op in methods.items():
        if method not in METHOD_ORDER or not isinstance(op, dict):
            continue
        op_count += 1
        tag = (op.get("tags") or ["ungrouped"])[0]
        groups[tag].append((path, method, op.get("summary") or ""))

from datetime import date as _date

lines = [
    "# REST API reference",
    "",
    f"Generated in-process from the application OpenAPI schema (`GET /api/openapi.json`) on {_date.today().isoformat()}:",
    f"**{len(paths)} paths, {op_count} operations** across {len(groups)} tagged groups.",
    "Re-generate after API changes; this file is a mirror of the schema, not a hand-maintained list.",
    "",
    "Current [execution, SSH and replay contracts](execution-and-replay.md) describe",
    "owner-bound cursors, fresh execution authority, durable receipts and explicit refusals.",
    "This schema snapshot does not certify a deployed production topology.",
    "",
    "## Conventions",
    "",
    "- Base path: `/api/v1`. Interactive docs: `/api/docs` (Swagger UI).",
    "- Auth: `POST /auth/login` `{username, password}` → cookie `cryptoscan_session` + `token`.",
    "  Send `Authorization: Bearer <token>` or rely on the cookie.",
    "- Development login: `admin` / `cryptoscan` (refused in production).",
    "- RBAC: 9 roles (superadmin, ciso, security_analyst, developer, auditor, business_owner,",
    "  scanner, readonly, supervisor); most read endpoints allow readonly+, exports/mutations are role-gated.",
    "- Multi-tenant SaaS: tenant-scoped requests resolve the organization from the session's",
    "  memberships or `X-Tenant-ID`; API keys minted inside a tenant are bound to it. See",
    "  [architecture/multi-tenancy.md](../architecture/multi-tenancy.md).",
    "- Pagination and export-integrity metadata are endpoint-specific; do not infer them",
    "  from this operation table. See [evidence packs](../user-guide/evidence-pack.md).",
    "- Export manifests are signed with compact JWS (`signature_jws`, RFC 7515; legacy",
    "  `signature_hmac` retained).",
    "",
]
for tag in sorted(groups):
    lines.append(f"## {tag}")
    lines.append("")
    lines.append("| Method | Path | Summary |")
    lines.append("|---|---|---|")
    for path, method, summary in sorted(groups[tag],
                                        key=lambda x: (x[0], METHOD_ORDER.get(x[1], 9))):
        lines.append(f"| `{method.upper()}` | `{path}` | {summary} |")
    lines.append("")

out = "docs/api-reference/rest-api.md"
open(out, "w").write("\n".join(lines))
print(f"WROTE {out}: {len(paths)} paths, {op_count} ops, {len(groups)} groups")
