"""Explicit approved network scope — fail-closed enforcement (spec 67 §3, §30).

CryptoScan never sweeps ``10.0.0.0/8`` implicitly. An observation run is only
permitted when a tenant has saved an approved scope naming the exact
destinations, protocols, allowed operations, traffic budget and validity
window. This module answers one question for every execution path:

    "Is this exact endpoint, port, protocol and operation inside the approved
     scope, right now?"

Anything it cannot positively confirm is refused. It is deliberately a pure
function over the stored scope document so it can be tested without packets.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

SCOPE_KEY_TEMPLATE = "network:crypto-scope:{tenant}:{inventory_id}"

_OPERATION_ALIASES = {
    "TLS": {"CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"},
    "MTLS": {"CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"},
    "HTTPS": {"CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"},
    "SSH": {"CONNECT", "SSH_BANNER"},
    "IPSEC": {"IKE_PROBE"},
    "IKE": {"IKE_PROBE"},
    "ESP": {"IKE_PROBE"},
}


class ScopeViolation(Exception):
    """Raised when a run falls outside the approved scope (§30 STOP conditions)."""

    def __init__(self, reason: str, code: str = "scope_violation", detail: dict[str, Any] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.code = code
        self.detail = detail or {}


def scope_key(tenant_id: str | None, inventory_id: str = "default") -> str:
    return SCOPE_KEY_TEMPLATE.format(tenant=tenant_id or "default", inventory_id=inventory_id)


def _as_utc(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def normalize_endpoint(value: str) -> str:
    """Canonical ``host:port`` for comparison; default port 443 like the prober."""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith("["):
        host, _, rest = raw[1:].partition("]")
        port = rest[1:] if rest.startswith(":") and rest[1:].isdigit() else "443"
        return f"[{host.strip('[].')}]:{port}"
    if raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            return f"{host.rstrip('.')}:{port}"
    return f"{raw.rstrip('.')}:443"


def operations_for(protocol: str) -> set[str]:
    return set(_OPERATION_ALIASES.get(str(protocol or "").upper(), {"CONNECT"}))


def check_scope(
    scope: dict[str, Any] | None,
    endpoints: Iterable[str],
    *,
    protocol: str = "TLS",
    operations: Iterable[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate a planned run against an approved scope.

    Returns the admission receipt on success; raises :class:`ScopeViolation`
    otherwise. ``scope=None`` means nothing was ever approved → refuse.
    """
    endpoint_list = [normalize_endpoint(item) for item in endpoints if str(item or "").strip()]
    if not endpoint_list:
        raise ScopeViolation("no destinations supplied", code="empty_targets")
    if not scope:
        raise ScopeViolation(
            "no approved network scope — CryptoScan refuses to probe until a scope names the exact destinations",
            code="scope_not_configured",
        )

    expired_at = _as_utc(scope.get("valid_until"))
    moment = now or datetime.now(timezone.utc)
    if expired_at is not None and moment > expired_at:
        raise ScopeViolation(
            f"scope expired at {expired_at.isoformat()} — re-approve before probing",
            code="scope_expired",
            detail={"valid_until": expired_at.isoformat()},
        )

    allowed_protocols = {str(p).upper() for p in scope.get("protocols") or ["TLS"]}
    wanted_protocol = str(protocol or "TLS").upper()
    if wanted_protocol not in allowed_protocols:
        raise ScopeViolation(
            f"protocol {wanted_protocol} is not in the approved scope",
            code="protocol_not_allowed",
            detail={"protocols": sorted(allowed_protocols)},
        )

    allowed_operations = {str(o).upper() for o in scope.get("allowed_operations") or []}
    requested = {str(o).upper() for o in (operations or operations_for(wanted_protocol))}
    missing = requested - allowed_operations
    if missing:
        raise ScopeViolation(
            f"operations not approved: {', '.join(sorted(missing))}",
            code="operation_not_allowed",
            detail={"allowed_operations": sorted(allowed_operations)},
        )

    approved_targets = {normalize_endpoint(item) for item in scope.get("destinations") or []}
    outside = [endpoint for endpoint in endpoint_list if endpoint not in approved_targets]
    if outside:
        raise ScopeViolation(
            f"{len(outside)} destination(s) outside the approved scope",
            code="destination_outside_scope",
            detail={"outside": outside, "approved": sorted(approved_targets)},
        )

    budget = scope.get("traffic_budget") or {}
    max_connections = int(budget.get("max_connections") or 0)
    if max_connections and len(endpoint_list) > max_connections:
        raise ScopeViolation(
            f"traffic budget exceeded: {len(endpoint_list)} connections requested, {max_connections} approved",
            code="traffic_budget_exceeded",
            detail={"requested": len(endpoint_list), "max_connections": max_connections},
        )

    return {
        "schema": "cryptoscan.network-scope-admission/1",
        "scope_name": scope.get("name"),
        "destinations": endpoint_list,
        "protocol": wanted_protocol,
        "operations": sorted(requested),
        "traffic_budget": {"max_connections": max_connections, "max_bytes": int(budget.get("max_bytes") or 0)},
        "valid_until": expired_at.isoformat() if expired_at else None,
        "checked_at": moment.isoformat(),
        "decision": "PERMITTED",
    }
