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


def start_automation_bridge() -> bool:
    """Start the bus->automation consumer on the running loop (idempotent)."""
    global _task
    if _task is not None:
        return False
    try:
        loop = asyncio.get_event_loop()
        _task = loop.create_task(_consumer())
        return True
    except RuntimeError:
        logger.debug("automation bridge start skipped (no running loop)")
        return False
