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


# --- scope revision diff -----------------------------------------------------
# Computed by the control plane only. A terminal that could compute this
# locally could also invent it, so the CLI only ever renders what this
# function returned.

def _entry_key(e: dict[str, Any]) -> str:
    return f"{e.get('kind', 'application')}:{e.get('target', '')}"


def _entry_payload(e: dict[str, Any]) -> dict[str, Any]:
    return {"enabled": bool(e.get("enabled", True)),
            "detail": e.get("detail") or {}}


def _excluded(target: str, exclusions: list[str] | tuple[str, ...]) -> str | None:
    """The first exclusion pattern covering this target, or None.

    Same matching rule as authorization (exact, prefix, CIDR) — a diff that
    disagreed with the authorize endpoint would be a second, kinder truth.
    """
    for x in exclusions:
        if x and _in_scope(target, x):
            return x
    return None


def diff_scope_revisions(
    from_entries: list[dict[str, Any]],
    from_envelope: dict[str, Any],
    to_entries: list[dict[str, Any]],
    to_envelope: dict[str, Any],
) -> dict[str, Any]:
    """Classify every declared scope unit between two revisions.

    Four verdicts, and none of them is a grant:

    * ``added``   — declared in the newer revision and effective (enabled,
      not excluded). The ``+`` rows.
    * ``removed`` — declared in the older revision and gone now. The ``−``
      rows. Whether it was effective before is named in the row.
    * ``changed`` — declared in both, with a different payload (enabled
      flag, detail, environment). The ``~`` rows carry before/after.
    * ``blocked`` — declared in the newer revision but NOT effective:
      disabled, or covered by an exclusion. The ``!`` rows. A blocked
      addition must never be read as a widening of authority.

    Envelope-level fields (allowed_methods, read_only, rate limit,
    maintenance window, exclusions) are reported separately in
    ``envelope_changed`` — same before/after shape, never silently dropped.
    """
    from_map = {_entry_key(e): e for e in from_entries}
    to_map = {_entry_key(e): e for e in to_entries}
    to_excl = [str(x) for x in (to_envelope.get("exclusions") or [])]
    from_excl = [str(x) for x in (from_envelope.get("exclusions") or [])]

    added: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []

    for key, e in to_map.items():
        target = str(e.get("target", ""))
        if key not in from_map:
            if not e.get("enabled", True):
                blocked.append({"kind": e.get("kind"), "target": target,
                                "reason": "disabled"})
                continue
            hit = _excluded(target, to_excl)
            if hit is not None:
                blocked.append({"kind": e.get("kind"), "target": target,
                                "reason": "excluded", "excluded_by": hit})
                continue
            added.append({"kind": e.get("kind"), "target": target,
                          **_entry_payload(e)})
            continue
        before = _entry_payload(from_map[key])
        after = _entry_payload(e)
        if before != after:
            changed.append({"kind": e.get("kind"), "target": target,
                            "before": before, "after": after})

    for key, e in from_map.items():
        if key not in to_map:
            was_effective = (bool(e.get("enabled", True))
                             and _excluded(str(e.get("target", "")), from_excl) is None)
            removed.append({"kind": e.get("kind"), "target": e.get("target"),
                            "was_effective": was_effective})

    # envelope fields — allowed_targets is derived from entries, skip it
    envelope_changed: dict[str, Any] = {}
    for field in ("allowed_methods", "read_only", "exclusions", "rate_limit",
                  "scanner", "maintenance_window_open"):
        before = from_envelope.get(field)
        after = to_envelope.get(field)
        if before != after:
            envelope_changed[field] = {"before": before, "after": after}

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "blocked": blocked,
        "envelope_changed": envelope_changed,
        "summary": {"added": len(added), "removed": len(removed),
                    "changed": len(changed), "blocked": len(blocked),
                    "envelope_fields_changed": len(envelope_changed)},
    }


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
