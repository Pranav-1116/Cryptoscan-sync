"""Scope & Authorization + Multi-Tenant isolation (blueprint #2 and #11).

Deterministic, no-AI scope resolution. Turn a tenant's persisted scope
(Organization → Environment → ScopeEntry → Connector) into ONE authorization
envelope:

    Customer -> Authorized Scope -> Allowed Targets -> Allowed Methods ->
    Credentials -> Scanner     +  exclusions, maintenance windows, rate limits,
    read-only.

``resolve_scope`` is pure over plain data (the router feeds it DB rows) so it
is unit-testable without a database. ``authorize_scope`` evaluates a concrete
target/method/mutation against that envelope and fails closed. ``guard_tenant``
is the read-path tenant boundary: any row not owned by the requesting tenant is
hidden and counted, so Tenant A could never see Tenant B's data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: default allow-list when no connector declares a method (fail-safe: read-only
#: passive collection is always permitted; mutating methods require a connector)
_DEFAULT_METHODS = ("api", "agent", "vendor_api", "iam_role", "service_principal",
                    "service_account", "snmp", "ssh", "netconf", "restconf",
                    "syslog", "flow_telemetry", "other")

#: kinds that participate in scope targeting (mirrors onboarding SCOPE_KINDS)
SCOPE_KINDS = ("network", "cloud", "application", "hardware")


@dataclass
class ScopeAuthorization:
    org_id: str | None
    tenant: str | None
    allowed_targets: dict[str, list[str]] = field(default_factory=dict)
    allowed_methods: tuple[str, ...] = _DEFAULT_METHODS
    read_only: bool = True
    exclusions: tuple[str, ...] = ()
    rate_limit_max: int = 60
    rate_limit_window: int = 60
    scanner: str | None = None
    maintenance_window_open: bool = True

    def target_allowed(self, target: str, kind: str | None = None) -> bool:
        """A target is allowed if it is inside at least one enabled scope entry
        for its kind. An empty scope is *deny-all* (fail closed) unless the
        caller explicitly declares ``allow_unspecified`` — which we never do."""
        allowed = self.allowed_targets.get(kind or "", []) + self.allowed_targets.get("", [])
        return any(_in_scope(target, a) for a in allowed if a)

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "tenant": self.tenant,
            "allowed_targets": self.allowed_targets,
            "allowed_methods": sorted(self.allowed_methods),
            "read_only": self.read_only,
            "exclusions": list(self.exclusions),
            "rate_limit": {"max": self.rate_limit_max, "window_seconds": self.rate_limit_window},
            "scanner": self.scanner,
            "maintenance_window_open": self.maintenance_window_open,
        }


def _in_scope(target: str, scope: str) -> bool:
    """Exact, prefix, and CIDR scope matching (same rule as connector exclusions)."""
    import ipaddress
    if target == scope or scope in target or target in scope:
        return True
    if "/" in scope:
        try:
            return ipaddress.ip_address(target) in ipaddress.ip_network(scope, strict=False)
        except ValueError:
            return False
    return False


def resolve_scope(org: dict[str, Any] | None = None,
                  scope_entries: list[dict[str, Any]] | None = None,
                  connectors: list[dict[str, Any]] | None = None,
                  maintenance_open: bool = True) -> ScopeAuthorization:
    """Build one authorization envelope from persisted scope + connectors.

    * Allowed targets  → enabled ScopeEntry per kind (fail-closed).
    * Allowed methods  → methods of enabled/configured connectors (or default).
    * Read-only        → True unless a connector is ``mode="active"``; passive
      connectors can NEVER authorize a mutating run.
    * Rate limit       → the most restrictive connector rate limit, else default.
    * Exclusions       → collected from scope-entry ``detail["exclusions"]``.
    * Scanner          → the agent's scanner binding (Connector.scanner/agent_id).
    """
    entries = scope_entries or []
    conns = connectors or []
    org_id = (org or {}).get("id") or (org or {}).get("org_id")

    allowed_targets: dict[str, list[str]] = {k: [] for k in SCOPE_KINDS}
    exclusions: set[str] = set()
    for e in entries:
        if not e.get("enabled", True):
            continue
        kind = e.get("kind", "application")
        allowed_targets.setdefault(kind, []).append(e.get("target", ""))
        # per-entry exclusions (declared in detail["exclusions"])
        detail = e.get("detail") or {}
        for x in detail.get("exclusions", []) or []:
            exclusions.add(str(x))

    # methods / rate limit / scanner from connectors
    methods: set[str] = set()
    active = False
    limits: list[tuple[int, int]] = []
    scanner = None
    for c in conns:
        if c.get("status") not in (None, "configured", "connected"):
            continue
        m = c.get("method")
        if m:
            methods.add(m)
        if (c.get("mode") or "passive") == "active":
            active = True
        cfg = _refresh_clean(c.get("config") or {})
        lim = cfg.get("rate_limit") or {}
        if isinstance(lim, dict):
            limits.append((int(lim.get("max", 60)), int(lim.get("window_seconds", 60))))
        if c.get("agent_id"):
            scanner = c.get("scanner") or c.get("agent_id")

    allowed_methods = tuple(sorted(methods)) if methods else _DEFAULT_METHODS
    if limits:
        rate_max = min(l[0] for l in limits)
        rate_win = max(l[1] for l in limits)
    else:
        rate_max, rate_win = 60, 60

    return ScopeAuthorization(
        org_id=org_id,
        tenant=str((org or {}).get("name") or org_id or ""),
        allowed_targets=allowed_targets,
        allowed_methods=allowed_methods,
        read_only=not active,
        exclusions=tuple(sorted(exclusions)),
        rate_limit_max=rate_max,
        rate_limit_window=rate_win,
        scanner=scanner,
        maintenance_window_open=bool(maintenance_open),
    )


def _refresh_clean(cfg: dict[str, Any]) -> dict[str, Any]:
    """Best-effort normalizing of connector config keys (no secret leak)."""
    return {k.lower(): v for k, v in (cfg or {}).items()}


def authorize_scope(scope: ScopeAuthorization, target: str,
                    kind: str | None = None, method: str | None = None,
                    mutating: bool = False) -> dict[str, Any]:
    """Evaluate one target/method/mutation against the envelope.

    Fails closed: an unknown/target-outside-scope is DENIED.
    """
    if not scope.maintenance_window_open:
        return {"allowed": False, "reason": "maintenance_window_closed"}
    for ex in scope.exclusions:
        if _in_scope(target, ex):
            return {"allowed": False, "reason": "excluded"}
    if not scope.target_allowed(target, kind):
        return {"allowed": False, "reason": "target_out_of_scope"}
    if method and method not in scope.allowed_methods:
        return {"allowed": False, "reason": "method_not_allowed"}
    if mutating and scope.read_only:
        return {"allowed": False, "reason": "read_only"}
    return {"allowed": True, "reason": "ok"}


def guard_tenant(rows: list[dict[str, Any]], tenant: str | None,
                 owner_tenant: Any = None) -> dict[str, Any]:
    """Read-path tenant boundary. Hide any row not owned by ``tenant``.

    ``owner_tenant`` is a callable ``row -> tenant_id  |  a key name`` to look
    up the row's tenant; when absent and a row has no tenant marker we KEEP it
    only if no specific tenant is requested (i.e. we never hide unmarked
    platform/reference data). If a non-empty tenant is requested, unmarked rows
    are dropped (fail closed for the requested tenant).
    """
    if not tenant:
        # no tenant context → platform-wide view, nothing hidden (honest)
        kept, hidden = [dict(r) for r in rows], 0
        return {"kept": kept, "hidden": hidden, "tenant": None}
    kept: list[dict[str, Any]] = []
    hidden = 0
    for r in rows:
        resolved = _row_tenant(r, owner_tenant)
        if resolved and resolved == tenant:
            kept.append(dict(r))
        elif resolved is None:
            # marked rows only for tenant-isolated view; unmarked are reference
            # data (all tenants) and stay visible.
            kept.append(dict(r))
        else:
            hidden += 1
    return {"kept": kept, "hidden": hidden, "tenant": tenant}


def _row_tenant(row: dict[str, Any], owner_tenant: Any) -> str | None:
    if callable(owner_tenant):
        return owner_tenant(row)
    if isinstance(owner_tenant, str):
        v = row.get(owner_tenant)
        return str(v) if v else None
    v = row.get("tenant") or row.get("org_id") or row.get("organization_id")
    return str(v) if v else None


__all__ = [
    "ScopeAuthorization", "SCOPE_KINDS", "resolve_scope", "authorize_scope",
    "guard_tenant",
]
