"""OpenAPI contract invariants (audit 11 — contract testing slice).

The duplicate-operationId defect this guards against is real history:
``GET /api/v1/container/scans`` (container.py) and ``GET
/api/v1/container-scans`` (container_scans.py) both derived the id
``list_container_scans_api_v1_container_scans_get`` because FastAPI
normalizes dashes and slashes to underscores — a duplicate operationId
breaks every client generated from the spec. The regeneration script only
prints a warning, so the invariant belongs in a test.
"""

from __future__ import annotations

import os


def _spec():
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-abc123")
    os.environ.setdefault("ALLOW_SQLITE", "true")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    from api.main import create_app

    return create_app().openapi()


def test_every_operation_id_is_unique():
    spec = _spec()
    ids: dict[str, list[str]] = {}
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            op_id = op.get("operationId")
            assert op_id, f"missing operationId: {method.upper()} {path}"
            ids.setdefault(op_id, []).append(f"{method.upper()} {path}")
    duplicates = {k: v for k, v in ids.items() if len(v) > 1}
    assert not duplicates, f"duplicate operationIds break generated clients: {duplicates}"


def test_spec_shape_invariants():
    spec = _spec()
    assert spec["info"]["title"]
    assert spec["openapi"].startswith("3.")
    # infrastructure probes are deliberately unversioned (no auth, no API
    # contract); everything else must sit under the versioned prefix
    unversioned_allowlist = {"/", "/health", "/healthz", "/metrics", "/ready", "/readyz"}
    for path, ops in spec["paths"].items():
        if path not in unversioned_allowlist:
            assert path.startswith("/api/v1"), f"non-versioned path in spec: {path}"
            for method, op in ops.items():
                if isinstance(op, dict):
                    # every versioned operation carries at least one tag
                    # (the grouping the regenerated reference doc uses)
                    assert op.get("tags"), f"untagged operation: {method.upper()} {path}"


def test_no_shadowed_trailing_slash_duplicates():
    """/x and /x/ must not expose the same derived operationId either."""
    spec = _spec()
    by_id: dict[str, set[str]] = {}
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            if isinstance(op, dict) and op.get("operationId"):
                by_id.setdefault(op["operationId"], set()).add(path)
    for op_id, paths in by_id.items():
        if len(paths) > 1:
            normalized = {p.rstrip("/") for p in paths}
            assert len(normalized) == len(paths) or len(paths) == 1, (
                f"operationId {op_id} shared by unrelated paths: {sorted(paths)}"
            )
