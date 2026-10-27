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
    if etype == "ticket.requested":
        # Automation → ITSM link (round 35): the engine announces ticket
        # requests on the bus; this consumer lands them as real Ticket
        # rows with the same signed fan-out as manual creation. Loop-safe:
        # it emits nothing back onto the bus.
        try:
            _consume_ticket_request(event)
        except Exception:
            logger.debug("ticket_request_consume_failed", exc_info=True)
        return
    if etype.startswith(_EMITTED_PREFIXES):
        return
    if etype == "telecom.event":
        # telecom posture events map onto the SAME rules engine via the
        # pure mapper (kind + condition data); noise returns None and the
        # automation engine is never woken for recoveries/info events.
        from telecom_scanner.automation import automation_data, automation_event_kind

        payload = event.get("payload") or {}
        kind = automation_event_kind(payload)
        if kind is None:
            return
        try:
            from db.connection.session import SessionLocal

            from api.routers.automation import run_automation

            with SessionLocal() as db:
                run_automation(
                    db,
                    event_kind=kind,
                    data=automation_data(payload),
                    asset=None,
                    triggered_by=f"event-bus:{event.get('source') or 'telecom-scanner'}",
                    persist=True,
                )
                db.commit()
        except Exception:
            logger.debug("telecom automation handling failed", exc_info=True)
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
    except Exception:
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
        except Exception:
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
                _cbom_sweep(db)
                _threat_intel_sweep(db)
                db.commit()
        except asyncio.CancelledError:
            break
        except Exception:
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


def _cbom_sweep(db) -> bool:
    """Version the live cryptographic inventory (idempotent).

    Runs after scan-derived evidence changes; appends a new content-addressed
    CBOM version only when the component set actually changed. Purely
    deterministic — the versioning tick makes the change/diff decision.
    """
    try:
        from api.routers.automation_ops import cbom_version_tick

        result = cbom_version_tick(db, observations=None, user="system-sweep")
        if result.get("changed"):
            _publish_bus("cbom.versioned", {
                "version": result.get("version"),
                "added": len(result.get("added") or []),
                "removed": len(result.get("removed") or [])})
        return bool(result.get("changed"))
    except Exception:
        logger.debug("cbom sweep tick failed", exc_info=True)
        return False


def _publish_bus(event_type: str, payload: dict) -> None:
    try:
        from api.events.bus import get_event_bus

        get_event_bus().publish(event_type, payload, source="automation-sweep")
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
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


def _threat_intel_sweep(db) -> int:
    """Sync configured threat-intel feeds on the sweep tick (deep/30).

    No-op when no feeds are configured (community default). A failing
    feed never breaks the sweep — the next tick retries.
    """
    from api.config.settings import get_settings

    settings = get_settings()
    raw = (settings.THREAT_INTEL_FEEDS or "").strip()
    if not raw:
        return 0
    feeds = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        name, _, url = part.partition("=")
        feeds.append({"name": name.strip() or url.strip(), "url": url.strip()})
    try:
        from api.routers.threat_intel import _upsert
        from vendor_intel.threat_intel import sync_feeds

        sync = sync_feeds(
            feeds,
            secret=settings.THREAT_INTEL_FEED_SECRET,
            timeout=float(settings.THREAT_INTEL_FEED_TIMEOUT or 15),
        )
        if sync["entries"]:
            _upsert(db, sync["entries"])
        return sync["feeds_ok"]
    except Exception:
        logger.debug("threat_intel_sweep_failed", exc_info=True)
        return 0


def _consume_ticket_request(event: dict) -> dict | None:
    """Land one `ticket.requested` bus event as an ITSM ticket row.

    Idempotent by external_ref: a redelivered event does not open a
    second ticket. Delivery fan-out reuses the enterprise ITSM machinery
    (registered integrations, signed HTTP, durable outbox on failure).
    """
    from sqlalchemy import select

    from db.connection.session import SessionLocal
    from db.models.enterprise import Ticket
    from db.repositories.enterprise_repository import EnterpriseRepository

    payload = event.get("payload") or {}
    event_kind = str(payload.get("event_kind") or "event")
    asset_id = payload.get("asset_id")
    ref = f"automation/{event_kind}/{asset_id or 'estate'}"
    severity = str(payload.get("severity") or "medium").lower()

    with SessionLocal() as db:
        existing = db.execute(
            select(Ticket).where(Ticket.external_ref == ref,
                                 Ticket.state != "closed")
        ).scalar_one_or_none()
        if existing is not None:
            return {"ticket_id": existing.id, "duplicate": True}
        repo = EnterpriseRepository(db)
        ticket = repo.create_ticket(
            provider="automation",
            title=f"[automation] {event_kind}"
                  + (f" — asset {asset_id}" if asset_id else ""),
            asset_id=asset_id,
            severity=severity,
            external_ref=ref,
            created_by=f"event-bus:{event.get('source') or 'system'}",
        )
        try:
            from api.routers.enterprise import _fan_out

            deliveries = _fan_out(db, "itsm.ticket_created", {
                "ticket": ticket.to_dict(), "asset_id": asset_id,
                "severity": ticket.severity, "detail": ticket.title,
            })
        except Exception:
            logger.debug("ticket_request_fanout_failed", exc_info=True)
            deliveries = []
        db.commit()
        return {"ticket_id": ticket.id, "duplicate": False,
                "deliveries": [d.get("status") for d in deliveries]}
