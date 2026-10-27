"""ABAC enforcement helpers — the runtime counterpart of ``iam.is_authorized``.

``iam`` produces allow/deny *decisions* for an explicit target. Enforcement in
the request path needs three more things, kept here as pure (side-effect-free)
functions so they are unit-testable without FastAPI or a database:

* :func:`action_for_method`  — HTTP verb/path -> grant action (read/write/scan).
* :func:`scope_from_payload` — extract a hierarchical target scope (Region ->
  Business Unit -> Environment -> Asset) from request params/body/headers.
* :func:`filter_rows`        — post-filter of list responses so a subject only
  ever sees rows inside a scope covered by one of their active grants.

Enforcement is fail-closed: an explicit deny always wins; allow requires a
matching active grant; rows with no scope attributes are treated as platform
reference data (algorithm catalogs, KB entries) and stay visible to every
authenticated caller.
"""

from __future__ import annotations

from typing import Any

from control_plane.iam import SCOPE_LEVELS, Scope, is_authorized, residency_permitted

#: scope attribute names accepted on payloads/rows (with common aliases).
_SCOPE_ALIASES = {
    "region": ("region", "region_code", "data_region", "residency_region"),
    "business_unit": ("business_unit", "bu", "business_unit_code", "businessunit"),
    "environment": ("environment", "env", "environment_code", "env_type"),
    "asset_id": ("asset_id", "asset", "assetid", "hostname", "fqdn", "system_id",
                 "target_id", "ci_id"),
    "tenant_id": ("tenant_id", "tenant", "customer_id"),
}

#: read-only verb set; everything else mutates.
_READ_METHODS = {"GET", "HEAD", "OPTIONS"}

#: path suffixes that submit/ingest scan data even though they are POSTs.
_SCAN_PATH_MARKERS = (
    "/scans/trigger", "/scans/runtime-findings", "/orchestrator/dispatch",
    "/discovery/start", "/hardware/ingest", "/runtime/ingest",
)


def action_for_method(method: str, path: str = "") -> str:
    """Map an HTTP verb (+path) to the grant action it needs.

    Scan *submission* (trigger/ingest/dispatch) is the ``scan`` action — the
    8-role catalog gives that to the scanner role. Plain reads are ``read``;
    every other mutating verb is ``write``.
    """
    verb = (method or "GET").upper()
    if verb in _READ_METHODS:
        return "read"
    lowered = (path or "").lower()
    if any(marker in lowered for marker in _SCAN_PATH_MARKERS):
        return "scan"
    return "write"


def scope_from_payload(*sources: dict[str, Any] | None) -> Scope:
    """Collect the most specific scope attributes found across ``sources``.

    Earlier sources take precedence (query/header before body). Values that
    are empty strings or dicts/lists are ignored.
    """
    found: dict[str, str | None] = {lvl: None for lvl in SCOPE_LEVELS}
    found["tenant_id"] = None
    for source in sources:
        if not source or not isinstance(source, dict):
            continue
        for level, aliases in _SCOPE_ALIASES.items():
            if found.get(level) is not None:
                continue
            for alias in aliases:
                val = source.get(alias)
                if isinstance(val, str) and val.strip():
                    found[level] = val.strip()
                    break
    return Scope(**found)


def row_scope(row: dict[str, Any]) -> Scope | None:
    """Return a scope for a response row, or None when it carries no scope
    attributes (platform/reference data — visible to all authenticated)."""
    scope = scope_from_payload(row)
    if all(getattr(scope, lvl) is None for lvl in (*SCOPE_LEVELS, "tenant_id")):
        return None
    return scope


def authorize_request(
    grants: list[dict[str, Any]],
    *,
    username: str,
    roles: list[str],
    method: str,
    path: str,
    scope: Scope,
    tenant: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Full enforcement decision for one request.

    Order: residency/sovereignty first, then explicit-deny/allow over grants.
    """
    action = action_for_method(method, path)
    if not residency_permitted(tenant, scope.region):
        return False, "denied: data residency / sovereignty violation"
    allowed, reason = is_authorized(
        grants, username=username, roles=roles, action=action, target=scope,
    )
    return allowed, reason


def _row_visible(grants, username, roles, row, tenant) -> bool:
    scope = row_scope(row)
    if scope is None:
        return True  # unscoped platform/reference data
    allowed, _ = authorize_request(
        grants, username=username, roles=roles, method="GET", path="",
        scope=scope, tenant=tenant,
    )
    return allowed


def filter_rows(
    grants: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    *,
    username: str,
    roles: list[str],
    tenant: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Post-filter a collection response to rows the caller may see.

    Returns ``(visible_rows, hidden_count)``. Applied only to list responses
    on scope-bearing collections; reference data (no scope attributes) always
    passes.
    """
    visible: list[dict[str, Any]] = []
    hidden = 0
    for row in rows:
        if not isinstance(row, dict):
            visible.append(row)
            continue
        if _row_visible(grants, username, roles, row, tenant):
            visible.append(row)
        else:
            hidden += 1
    return visible, hidden


def effective_scopes(grants: list[dict[str, Any]], *, username: str,
                     roles: list[str]) -> list[dict[str, Any]]:
    """The active allow-grants that belong to this user or one of their roles
    — used by the /control/me/grants endpoint so the console can show a user
    exactly which Region→BU→Environment→Asset surface they can reach."""
    out: list[dict[str, Any]] = []
    for g in grants:
        if not g.get("is_active", True) or g.get("effect", "allow") != "allow":
            continue
        stype = g.get("subject_type", "user")
        subj = g.get("subject")
        belongs = (subj == "*") or (stype == "role" and subj in roles) or (
            stype != "role" and subj == username
        )
        if not belongs:
            continue
        out.append({
            "actions": g.get("actions") or [],
            "region": g.get("region"),
            "business_unit": g.get("business_unit"),
            "environment": g.get("environment"),
            "asset_id": g.get("asset_id"),
            "tenant_id": g.get("tenant_id"),
            "subject": subj,
            "subject_type": stype,
        })
    return out
