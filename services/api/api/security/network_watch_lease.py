"""Database lease for the network observation scheduler (spec 67 §30, §31).

Why this exists: the §30 STOP switch and the observation worker are
``distributed: false`` today. In a bank deployment the API runs more than once,
and two replicas sharing one approved scope will happily probe the same
endpoints twice — doubling traffic against a budget that was approved for one
run, which is a scope violation even when every individual probe is in scope.

The lease is deliberately small and honest:

* one row in ``AppSetting`` per tenant holds ``{owner, expires_at, ttl}``;
* a worker may tick only while it holds a non-expired lease (or renews it);
* the lease expires by itself, so a crashed worker cannot block observation
  forever — but an expired lease is reported, not hidden;
* it is a **single-writer lease over a shared database**, not a consensus
  protocol. It makes double-probing unlikely and visible; it does not make the
  fleet leader-elected. ``mode: "DATABASE_LEASE"`` is what the API reports.
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

SCHEMA = "cryptoscan.network-watch-lease/1"
MODE = "DATABASE_LEASE"
MIN_TTL = 60
MAX_TTL = 3600
DEFAULT_TTL = 180


class LeaseError(RuntimeError):
    """Raised when a lease operation cannot be completed honestly."""

    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(reason)


def lease_key(tenant_id: str | None) -> str:
    return f"network:watch-lease:{tenant_id or 'global'}"


def default_owner() -> str:
    host = os.environ.get("HOSTNAME") or (socket.gethostname() if hasattr(socket, "gethostname") else "unknown")
    return f"{host}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _read(db, tenant_id: str | None) -> dict[str, Any] | None:
    from sqlalchemy import select

    from db.models.app_setting import AppSetting

    row = db.execute(select(AppSetting).where(AppSetting.key == lease_key(tenant_id))).scalars().first()
    if row is None or not row.value:
        return None
    try:
        payload = json.loads(row.value)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _write(db, tenant_id: str | None, payload: dict[str, Any], user: str | None) -> None:
    from sqlalchemy import select

    from db.models.app_setting import AppSetting

    key = lease_key(tenant_id)
    value = json.dumps(payload, default=str)
    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None:
        db.add(AppSetting(key=key, value=value, updated_by=user))
    else:
        row.value = value
        row.updated_by = user
    db.commit()


def _clamp(ttl: int | None) -> int:
    try:
        value = int(ttl if ttl is not None else DEFAULT_TTL)
    except (TypeError, ValueError):
        value = DEFAULT_TTL
    return max(MIN_TTL, min(MAX_TTL, value))


def _describe(lease: dict[str, Any] | None, now: datetime) -> dict[str, Any]:
    if not lease:
        return {"held": False, "holder": None, "expires_at": None, "expired": True, "expires_in_seconds": 0}
    expires = _parse(lease.get("expires_at"))
    expired = expires is None or expires <= now
    return {
        "held": not expired,
        "holder": lease.get("owner"),
        "expires_at": lease.get("expires_at"),
        "expired": expired,
        "expires_in_seconds": max(0, int((expires - now).total_seconds())) if expires else 0,
        "acquired_at": lease.get("acquired_at"),
        "renewed_at": lease.get("renewed_at"),
        "ttl_seconds": lease.get("ttl_seconds"),
        "inventory_id": lease.get("inventory_id"),
    }


def acquire(
    db,
    *,
    tenant_id: str | None,
    owner: str | None = None,
    ttl_seconds: int | None = None,
    inventory_id: str | None = None,
    user: str | None = None,
) -> dict[str, Any]:
    """Acquire or renew the single-writer lease for this tenant."""
    now = _now()
    ttl = _clamp(ttl_seconds)
    owner = (owner or default_owner())[:200]
    current = _read(db, tenant_id)
    state = _describe(current, now)
    if state["held"] and state["holder"] != owner:
        return {
            "schema": SCHEMA,
            "mode": MODE,
            "acquired": False,
            "outcome": "HELD_BY_OTHER",
            "owner": owner,
            "lease": state,
            "reason": (
                f"another worker ({state['holder']}) holds the network observation lease for "
                f"{state['expires_in_seconds']} more second(s) — refusing to double-probe the approved scope"
            ),
            "distributed": True,
        }
    renewed = bool(current and state["holder"] == owner and not state["expired"])
    payload = {
        "schema": SCHEMA,
        "mode": MODE,
        "owner": owner,
        "tenant": tenant_id or "global",
        "ttl_seconds": ttl,
        "inventory_id": inventory_id or (current or {}).get("inventory_id"),
        "acquired_at": (current or {}).get("acquired_at") if renewed else now.isoformat(),
        "renewed_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl)).isoformat(),
    }
    _write(db, tenant_id, payload, user)
    return {
        "schema": SCHEMA,
        "mode": MODE,
        "acquired": True,
        "outcome": "RENEWED" if renewed else "ACQUIRED",
        "owner": owner,
        "lease": _describe(payload, now),
        "reason": (
            "the lease was renewed by its holder"
            if renewed
            else "the previous lease was absent or expired — this worker is now the single writer"
        ),
        "distributed": True,
    }


def release(db, *, tenant_id: str | None, owner: str, user: str | None = None) -> dict[str, Any]:
    now = _now()
    current = _read(db, tenant_id)
    state = _describe(current, now)
    if current is None:
        return {
            "schema": SCHEMA,
            "mode": MODE,
            "released": False,
            "outcome": "NO_LEASE",
            "reason": "no lease exists for this tenant",
            "lease": state,
        }
    if state["holder"] != owner:
        return {
            "schema": SCHEMA,
            "mode": MODE,
            "released": False,
            "outcome": "NOT_OWNER",
            "reason": f"the lease is held by {state['holder']} — only the holder can release it",
            "lease": state,
        }
    payload = {**current, "released_at": now.isoformat(), "expires_at": now.isoformat()}
    _write(db, tenant_id, payload, user)
    return {
        "schema": SCHEMA,
        "mode": MODE,
        "released": True,
        "outcome": "RELEASED",
        "lease": _describe(payload, now),
        "reason": "the holder released the lease; another worker may now acquire it",
    }


def status(db, *, tenant_id: str | None) -> dict[str, Any]:
    now = _now()
    lease = _read(db, tenant_id)
    state = _describe(lease, now)
    return {
        "schema": SCHEMA,
        "mode": MODE,
        "scheduling": MODE,
        "distributed": True,
        "lease": state,
        "owner_hint": default_owner(),
        "limitations": [
            "a database lease coordinates workers that share this database; it is not leader election",
            "an expired lease is reported as expired, never silently reused",
            "the in-process watch thread is still per-replica — call POST /network/crypto-watch/tick "
            "from one scheduler to get single-writer behaviour",
        ],
    }


__all__ = [
    "DEFAULT_TTL",
    "MAX_TTL",
    "MIN_TTL",
    "MODE",
    "SCHEMA",
    "LeaseError",
    "acquire",
    "default_owner",
    "lease_key",
    "release",
    "status",
]
