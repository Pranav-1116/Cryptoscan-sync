"""Durable bookkeeping for the two security monitors that used to be lists.

``auth_monitor`` and ``vault.RESOLUTION_LOG`` stay in-memory on the fast
path — a login refusal and a secret probe must never wait on a database.
This module is the durable side: best-effort persistence of the same
observations, and hydration that rebuilds the in-memory state after a
restart. Every function degrades gracefully: a database that is down
loses bookkeeping, never behavior — and the failure is logged, not
hidden.

Tables (migration 0163): ``security_auth_events`` (failed-auth stamps
the suspicious-access window is rebuilt from) and
``vault_resolution_records`` (resolution observations the rotation
staleness watch reads).
"""
from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

#: how long failure stamps stay for forensics; the verdict window itself
#: is auth_monitor.WINDOW_SECONDS (hydrate reads only that much)
AUTH_EVENT_RETENTION_SECONDS = 24 * 3600.0
#: resolution observations must outlive the longest rotation window (90d)
RESOLUTION_RETENTION_DAYS = 180


def _session(db: Any = None):
    if db is not None:
        return db, False
    from db.connection.session import SessionLocal

    return SessionLocal(), True


def persist_auth_failure(user: str, source: str, *, occurred_at: float | None = None,
                         db: Any = None) -> bool:
    """Best-effort insert of one failed-auth stamp. Never raises."""
    try:
        from db.models.security_state import SecurityAuthEvent

        session, owned = _session(db)
        try:
            session.add(SecurityAuthEvent(
                user_key=user or "unknown",
                source=source or "unknown",
                occurred_at=time.time() if occurred_at is None else float(occurred_at),
            ))
            session.commit()
            return True
        finally:
            if owned:
                session.close()
    except Exception as exc:  # noqa: BLE001 - bookkeeping must never break the path
        logger.warning("auth_failure_persist_failed",
                       extra={"error_type": type(exc).__name__})
        return False


def hydrate_auth_monitor(*, db: Any = None, now: float | None = None) -> int:
    """Rebuild the suspicious-access window from the durable stamps.

    Returns the number of stamps restored. Rows older than the window
    cannot change a verdict; rows past the retention horizon are pruned.
    """
    from api.security import auth_monitor

    moment = time.time() if now is None else float(now)
    restored = 0
    try:
        from sqlalchemy import select

        from db.models.security_state import SecurityAuthEvent

        session, owned = _session(db)
        try:
            rows = session.execute(select(
                SecurityAuthEvent.user_key,
                SecurityAuthEvent.source,
                SecurityAuthEvent.occurred_at,
            ).where(SecurityAuthEvent.occurred_at >=
                    moment - auth_monitor.WINDOW_SECONDS)).all()
            restored = auth_monitor.hydrate(
                (user, source, stamp) for user, source, stamp in rows)
            session.query(SecurityAuthEvent).filter(
                SecurityAuthEvent.occurred_at <
                moment - AUTH_EVENT_RETENTION_SECONDS).delete()
            session.commit()
        finally:
            if owned:
                session.close()
    except Exception as exc:  # noqa: BLE001 - start without bookkeeping, not blind
        logger.warning("auth_monitor_hydrate_failed",
                       extra={"error_type": type(exc).__name__})
    return restored


def persist_resolution(provider: str, reference: str, outcome: str, *,
                       kind: str = "probe", resolved_at: str | None = None,
                       db: Any = None) -> bool:
    """Best-effort insert of one resolution observation. Never raises."""
    try:
        from datetime import datetime, timezone

        from db.models.security_state import VaultResolutionRecord

        session, owned = _session(db)
        try:
            session.add(VaultResolutionRecord(
                provider=provider,
                reference=reference,
                outcome=outcome,
                kind=kind,
                resolved_at=resolved_at or datetime.now(timezone.utc).isoformat(),
            ))
            session.commit()
            return True
        finally:
            if owned:
                session.close()
    except Exception as exc:  # noqa: BLE001 - bookkeeping must never break the probe
        logger.warning("resolution_persist_failed",
                       extra={"error_type": type(exc).__name__})
        return False


def hydrate_resolution_log(*, db: Any = None) -> int:
    """Rebuild ``vault.RESOLUTION_LOG`` from the durable observations.

    Returns the number of records restored. Retention pruning keeps the
    table no larger than the longest staleness window needs.
    """
    from api.security import vault

    restored = 0
    try:
        from datetime import datetime, timedelta, timezone

        from sqlalchemy import select

        from db.models.security_state import VaultResolutionRecord

        session, owned = _session(db)
        try:
            rows = session.execute(select(
                VaultResolutionRecord.provider,
                VaultResolutionRecord.reference,
                VaultResolutionRecord.outcome,
                VaultResolutionRecord.kind,
                VaultResolutionRecord.resolved_at,
            )).all()
            restored = vault.RESOLUTION_LOG.hydrate(
                {"provider": provider, "reference": reference,
                 "outcome": outcome, "kind": kind, "resolved_at": resolved_at}
                for provider, reference, outcome, kind, resolved_at in rows)
            horizon = (datetime.now(timezone.utc) -
                       timedelta(days=RESOLUTION_RETENTION_DAYS)).isoformat()
            session.query(VaultResolutionRecord).filter(
                VaultResolutionRecord.resolved_at < horizon).delete()
            session.commit()
        finally:
            if owned:
                session.close()
    except Exception as exc:  # noqa: BLE001 - start without bookkeeping, not blind
        logger.warning("resolution_hydrate_failed",
                       extra={"error_type": type(exc).__name__})
    return restored


def hydrate_all(*, db: Any = None) -> dict[str, int]:
    """Startup hook: both monitors rebuilt from their durable side."""
    return {
        "auth_events": hydrate_auth_monitor(db=db),
        "resolution_records": hydrate_resolution_log(db=db),
    }
