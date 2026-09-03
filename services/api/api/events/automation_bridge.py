"""Live bridge: platform bus events drive the deterministic automation engine.

Subscribes to the in-process event bus and maps a curated set of platform event
types onto automation event kinds, then builds and persists an automation plan.
Auto (observe/analyze/recommend) actions are fanned back onto the bus; EXECUTE/
APPROVE actions raise a governance approval (never auto-run).

Deterministic and no-AI. Recursion is prevented structurally: this bridge only
reacts to a fixed source-event allowlist and never re-consumes the fan-out events
the automation engine itself emits.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

#: platform bus event type -> automation event kind
EVENT_MAP = {
    "certificate.expiring": "certificate_expiring",
    "certificate.expired": "certificate_expiring",
    "certificate.changed": "certificate_changed",
    "crypto.asset_detected": "crypto_asset_detected",
    "asset.discovered": "new_asset",
    "asset.unauthorized": "new_asset",
    "drift.detected": "drift_detected",
    "baseline.drift": "drift_detected",
    "vuln.library_detected": "vulnerable_library_detected",
    "quantum.vulnerable_detected": "quantum_vulnerable_detected",
    "anomaly.detected": "anomaly_detected",
    "sla.breaches_present": "sla_breached",
    "ot.safety_denied": "anomaly_detected",
    "connector_failed": "connector_failed",
    "agent_offline": "agent_offline",
}

#: event prefixes the engine emits — never re-processed (loop prevention).
_EMITTED_PREFIXES = (
    "automation.", "alert.", "scan.targeted", "ticket.", "cbom.", "pqc.",
)

_task: asyncio.Task | None = None


def _handle(event: dict) -> None:
    etype = str(event.get("type") or "")
    if etype.startswith(_EMITTED_PREFIXES):
        return
    kind = EVENT_MAP.get(etype)
    if kind is None:
        return
    try:
        from db.connection.session import SessionLocal

        from api.routers.automation import run_automation

        payload = event.get("payload") or {}
        with SessionLocal() as db:
            run_automation(
                db,
                event_kind=kind,
                data=payload.get("data") or payload,
                asset=payload.get("asset"),
                triggered_by=f"event-bus:{event.get('source') or 'system'}",
                persist=True,
            )
            db.commit()
    except Exception:  # noqa: BLE001 — automation must never break the request path
        logger.debug("automation bridge handling failed for %s", etype, exc_info=True)


async def _consumer() -> None:
    from api.events.bus import get_event_bus

    sub = get_event_bus().subscribe()
    while True:
        try:
            event = await asyncio.wait_for(sub.queue.get(), timeout=1.0)
            await asyncio.to_thread(_handle, event)
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
        except Exception:  # noqa: BLE001
            await asyncio.sleep(0.5)


async def _sweep(interval: float = 900.0) -> None:
    """Periodic deterministic automation sweep (cert expiry + due scans)."""
    # first sweep shortly after start, then on the interval
    await asyncio.sleep(5.0)
    while True:
        try:
            from db.connection.session import SessionLocal

            with SessionLocal() as db:
                _cert_sweep(db)
                db.commit()
        except asyncio.CancelledError:
            break
        except Exception:  # noqa: BLE001
            logger.debug("automation sweep tick failed", exc_info=True)
        await asyncio.sleep(interval)


def _cert_sweep(db) -> int:
    """Emit certificate.expiring bus events for live certificates at threshold."""
    from sqlalchemy import select

    from automation.watchers.cert_expiry import watch_certificates
    from db.models.certificate import Certificate

    rows = db.execute(select(Certificate).limit(100_000)).scalars().all()
    certs = [{
        "id": r.id, "not_after": r.not_after.isoformat() if r.not_after else None,
        "public_key_algorithm": r.public_key_algorithm,
        "public_key_size": r.public_key_size,
        "is_self_signed": r.is_self_signed,
    } for r in rows]
    report = watch_certificates(certs)
    for alert in report.alerts:
        _publish_bus("certificate.expiring", {
            "cert_id": alert["cert_id"],
            "days_remaining": alert["days_remaining"],
            "severity": alert["severity"], "state": alert["state"],
            "reasons": alert["reasons"],
        })
    return len(report.alerts)


def _publish_bus(event_type: str, payload: dict) -> None:
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish(event_type, payload, source="automation-sweep")
    except Exception:  # noqa: BLE001
        pass


_sweep_task: asyncio.Task | None = None


def start_automation_bridge(sweep_interval: float = 900.0) -> bool:
    """Start the bus->automation consumer and the periodic sweep (idempotent)."""
    global _task, _sweep_task
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        logger.debug("automation bridge start skipped (no running loop)")
        return False
    if _task is None:
        _task = loop.create_task(_consumer())
    if _sweep_task is None and sweep_interval > 0:
        _sweep_task = loop.create_task(_sweep(sweep_interval))
    return True
