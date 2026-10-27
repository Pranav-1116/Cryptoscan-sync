"""Traffic-budget accounting for approved network observation (spec 67 §3, §30).

The approved scope states a budget (``max_connections`` / ``max_bytes``). That
number is only meaningful if something counts. This module keeps a rolling
per-scope usage window in the tenant's setting store and answers:

    "may this run spend N more connections / B more bytes right now?"

Reservation happens *before* the probe and settlement *after* it, so a run that
crashes still consumed its connections. A failed settlement is never silently
dropped: the caller is told, and the window stays charged.

This is deliberately a single-process, database-backed counter — not a
distributed quota service. It is honest about that: ``distributed: false`` is
returned with every receipt.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.security.network_scope import ScopeViolation, scope_key

#: rolling accounting window per scope
DEFAULT_WINDOW_SECONDS = 24 * 3600


class BudgetExhausted(ScopeViolation):
    """The approved traffic budget for this window is already spent."""

    def __init__(self, reason: str, detail: dict[str, Any] | None = None):
        super().__init__(reason, code="traffic_budget_exhausted", detail=detail or {})


def budget_key(tenant_id: str | None, inventory_id: str = "default") -> str:
    return scope_key(tenant_id, inventory_id).replace("crypto-scope", "crypto-budget")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _read(db: Session, key: str) -> dict[str, Any] | None:
    from db.models.app_setting import AppSetting

    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None or not row.value:
        return None
    try:
        payload = json.loads(row.value)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _write(db: Session, key: str, payload: dict[str, Any], user: str | None) -> None:
    from db.models.app_setting import AppSetting

    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None:
        db.add(AppSetting(key=key, value=json.dumps(payload), updated_by=user))
    else:
        row.value = json.dumps(payload)
        row.updated_by = user
    db.commit()


def _blank(now: datetime) -> dict[str, Any]:
    return {
        "window_started_at": now.isoformat(),
        "connections_used": 0,
        "bytes_used": 0,
        "runs": 0,
    }


def _roll(payload: dict[str, Any] | None, now: datetime, window_seconds: int) -> dict[str, Any]:
    """Start a new window when the previous one has elapsed."""
    if not payload:
        return _blank(now)
    try:
        started = datetime.fromisoformat(str(payload.get("window_started_at")).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return _blank(now)
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    if now - started >= timedelta(seconds=window_seconds):
        return _blank(now)
    return {
        "window_started_at": started.isoformat(),
        "connections_used": int(payload.get("connections_used") or 0),
        "bytes_used": int(payload.get("bytes_used") or 0),
        "runs": int(payload.get("runs") or 0),
    }


def state(
    db: Session,
    *,
    tenant_id: str | None,
    inventory_id: str = "default",
    limit: dict[str, Any] | None = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Current window usage plus remaining budget (read-only)."""
    moment = now or _now()
    key = budget_key(tenant_id, inventory_id)
    usage = _roll(_read(db, key), moment, window_seconds)
    max_connections = int((limit or {}).get("max_connections") or 0)
    max_bytes = int((limit or {}).get("max_bytes") or 0)
    return {
        "schema": "cryptoscan.network-budget/1",
        "inventory_id": inventory_id,
        **usage,
        "window_seconds": window_seconds,
        "max_connections": max_connections,
        "max_bytes": max_bytes,
        "connections_remaining": max(0, max_connections - usage["connections_used"]) if max_connections else None,
        "bytes_remaining": max(0, max_bytes - usage["bytes_used"]) if max_bytes else None,
        "exhausted": bool(
            (max_connections and usage["connections_used"] >= max_connections)
            or (max_bytes and usage["bytes_used"] >= max_bytes)
        ),
        "distributed": False,
    }


def check(
    db: Session,
    scope: dict[str, Any] | None,
    *,
    inventory_id: str = "default",
    connections: int = 0,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Raise :class:`BudgetExhausted` when this run would exceed the budget."""
    if not scope:
        raise BudgetExhausted("no approved scope — there is no budget to spend")
    limit = scope.get("traffic_budget") or {}
    current = state(
        db,
        tenant_id=scope.get("_tenant"),
        inventory_id=inventory_id,
        limit=limit,
        window_seconds=window_seconds,
        now=now,
    )
    max_connections = current["max_connections"]
    if max_connections and current["connections_used"] + connections > max_connections:
        raise BudgetExhausted(
            f"traffic budget spent: {current['connections_used']}/{max_connections} connections used in this window",
            detail={"budget": current, "requested": connections},
        )
    max_bytes = current["max_bytes"]
    if max_bytes and current["bytes_used"] >= max_bytes:
        raise BudgetExhausted(
            f"byte budget spent: {current['bytes_used']}/{max_bytes} bytes used in this window",
            detail={"budget": current},
        )
    return current


def reserve(
    db: Session,
    scope: dict[str, Any] | None,
    *,
    inventory_id: str = "default",
    connections: int = 0,
    user: str | None = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Charge ``connections`` to the window now; returns the updated usage."""
    current = check(
        db,
        scope,
        inventory_id=inventory_id,
        connections=connections,
        window_seconds=window_seconds,
        now=now,
    )
    payload = {
        "window_started_at": current["window_started_at"],
        "connections_used": current["connections_used"] + int(connections),
        "bytes_used": current["bytes_used"],
        "runs": current["runs"] + 1,
    }
    _write(db, budget_key(scope.get("_tenant"), inventory_id), payload, user)
    return {
        **current,
        "connections_used": payload["connections_used"],
        "runs": payload["runs"],
        "connections_remaining": max(0, current["max_connections"] - payload["connections_used"])
        if current["max_connections"]
        else None,
        "reserved": int(connections),
    }


def settle(
    db: Session,
    scope: dict[str, Any] | None,
    *,
    inventory_id: str = "default",
    connections: int = 0,
    bytes_used: int = 0,
    user: str | None = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Record what the run actually spent (bytes are only known afterwards)."""
    if not scope:
        return {"settled": False, "reason": "no approved scope"}
    key = budget_key(scope.get("_tenant"), inventory_id)
    usage = _roll(_read(db, key), now or _now(), window_seconds)
    payload = {
        "window_started_at": usage["window_started_at"],
        "connections_used": usage["connections_used"] + int(connections),
        "bytes_used": usage["bytes_used"] + int(bytes_used),
        "runs": usage["runs"],
    }
    _write(db, key, payload, user)
    return {"settled": True, **payload, "added_connections": int(connections), "added_bytes": int(bytes_used)}
