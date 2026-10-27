"""Emergency stop for network observation (spec 67 §30).

The approved scope bounds *what* may be observed. This module bounds *whether*
anything may be observed at all — the operator-facing STOP switch.

    IDS alert → STOP / ESCALATE / CORRELATE
    never     → disable the IDS

When engaged, every active network path (TLS observation, SSH, IPsec, protocol
detection, the continuous worker) refuses **before opening a socket**, with the
same ``network_observation_stopped`` code so an SOC can see one reason
everywhere. Passive metadata ingest and configuration import stay available:
they open no connection, and refusing them would blind the estate exactly when
it matters most.

State lives in the tenant setting store next to the scope; it is a local switch,
not a distributed kill switch (``distributed: false``).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

SAFETY_SCHEMA = "cryptoscan.network-safety/1"
STOP_CODE = "network_observation_stopped"


def safety_key(tenant_id: str | None) -> str:
    return f"network:safety:{tenant_id or 'global'}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class NetworkStopped(Exception):
    """Active observation is stopped by the operator."""

    code = STOP_CODE

    def __init__(self, reason: str, detail: dict[str, Any] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}


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


def state(db: Session, *, tenant_id: str | None) -> dict[str, Any]:
    """Current STOP state (read-only, always safe to call)."""
    payload = _read(db, safety_key(tenant_id)) or {}
    engaged = bool(payload.get("engaged"))
    return {
        "schema": SAFETY_SCHEMA,
        "engaged": engaged,
        "reason": payload.get("reason"),
        "engaged_by": payload.get("engaged_by"),
        "engaged_at": payload.get("engaged_at"),
        "released_by": payload.get("released_by"),
        "released_at": payload.get("released_at"),
        "release_note": payload.get("release_note"),
        "active_observation_permitted": not engaged,
        "passive_ingest_permitted": True,
        "config_import_permitted": True,
        "distributed": False,
        "boundary": (
            "one local switch per tenant; it refuses active probes before any socket is opened. "
            "Passive ingest and configuration import stay available because they open no connection"
        ),
    }


def engage(
    db: Session,
    *,
    reason: str,
    by: str,
    tenant_id: str | None,
) -> dict[str, Any]:
    """Stop all active network observation for this tenant."""
    payload = {
        "engaged": True,
        "reason": (reason or "operator emergency stop")[:400],
        "engaged_by": by,
        "engaged_at": _now(),
        "released_by": None,
        "released_at": None,
        "release_note": None,
    }
    _write(db, safety_key(tenant_id), payload, by)
    return state(db, tenant_id=tenant_id)


def release(
    db: Session,
    *,
    by: str,
    note: str | None = None,
    tenant_id: str | None,
) -> dict[str, Any]:
    """Re-open active observation; the release is attributed and timestamped."""
    payload = _read(db, safety_key(tenant_id)) or {}
    payload.update(
        {
            "engaged": False,
            "released_by": by,
            "released_at": _now(),
            "release_note": (note or "")[:400] or None,
        }
    )
    _write(db, safety_key(tenant_id), payload, by)
    return state(db, tenant_id=tenant_id)


def require_running(db: Session, *, tenant_id: str | None) -> dict[str, Any]:
    """Raise :class:`NetworkStopped` when the switch is engaged."""
    current = state(db, tenant_id=tenant_id)
    if current["engaged"]:
        raise NetworkStopped(
            current["reason"] or "network observation is stopped by the operator",
            detail={
                "engaged_by": current["engaged_by"],
                "engaged_at": current["engaged_at"],
                "action": "release the stop before running active probes",
            },
        )
    return current
