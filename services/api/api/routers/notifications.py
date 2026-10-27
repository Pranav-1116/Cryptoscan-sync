"""Notification routing preferences (spec §37).

Persists the per-tenant event-class -> channel routing (in-app / email /
webhook / SIEM) chosen in the console. Stored as an AppSetting (JSON) so the
routing survives restarts and is read by the delivery layer. No secrets here —
channel destinations are configured separately under /enterprise/integrations.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

router = APIRouter(prefix="/notifications", tags=["notifications"])

from control_plane.notification_routing import (
    CATALOG as CATALOG, CHANNELS as CHANNELS, EVENT_CLASS_MAP as EVENT_CLASS_MAP,
    CHANNEL_KINDS as CHANNEL_KINDS, ROUTING_SETTING_KEY as ROUTING_SETTING_KEY,
    merged_routing, save_routing,
)


class RoutingItem(BaseModel):
    id: str
    name: str
    severity: str = "INFO"
    channels: dict[str, bool] = Field(default_factory=dict)


class RoutingPayload(BaseModel):
    routing: list[RoutingItem]


def _merged(db: Session) -> tuple[list[dict], bool]:
    return merged_routing(db)


@router.get("/catalog")
def get_catalog(user: str = Depends(get_current_user)):
    """The canonical event-class catalog with default channel routing."""
    return {"catalog": CATALOG, "channels": list(CHANNELS)}


@router.get("/routing")
def get_routing(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    merged, persisted = _merged(db)
    return {"routing": merged, "persisted": persisted}


@router.put("/routing")
def put_routing(body: RoutingPayload, user: str = Depends(require_roles("superadmin", "admin", "ciso")), db: Session = Depends(get_db_session)):
    # normalize channels to the four known destinations
    allowed = {"inApp", "email", "webhook", "siem"}
    cleaned = []
    for item in body.routing:
        cleaned.append({
            "id": item.id,
            "name": item.name,
            "severity": item.severity,
            "channels": {k: bool(v) for k, v in item.channels.items() if k in allowed},
        })
    save_routing(db, cleaned, user=user)
    db.commit()
    return {"ok": True, "routing": cleaned, "count": len(cleaned), "updated_by": user}


@router.get("/feed")
def notification_feed(
    limit: int = 50,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The IN-APP channel delivery (§5, round 76).

    Until now the routing matrix persisted channel preferences that
    nothing consumed, and verification outcomes raised no notifications.
    This endpoint makes the in-app routing LOAD-BEARING: it reads the
    durable monitor journal (the same rows the events stream replays),
    maps each emitted event_type to its catalog class through
    EVENT_CLASS_MAP, and returns only events whose class the tenant has
    routed to in-app — so switching a class off in the matrix above
    actually removes it from the feed.

    Honest scope: email / webhook / SIEM channels are routing
    configuration stored here; their delivery runs through the
    integrations surface, not this endpoint. Emitted event types with no
    catalog mapping are NOT force-fit — they remain visible in the
    events stream, unrouted.
    """
    from db.models.monitor import MonitorEvent
    from db.tenancy import current_tenant

    merged, _persisted = _merged(db)
    routed = {entry["id"]: entry for entry in merged if entry["channels"].get("inApp")}

    bounded = max(1, min(int(limit or 50), 200))
    rows = (
        db.query(MonitorEvent)
        .filter(MonitorEvent.tenant_id == current_tenant(),
                MonitorEvent.event_type.in_([event_type for event_type, event_class in EVENT_CLASS_MAP.items()
                                            if event_class in routed]))
        .order_by(MonitorEvent.created_at.desc(), MonitorEvent.id.desc())
        .limit(bounded)
        .all()
    )
    items = []
    for row in rows:
        event_class = EVENT_CLASS_MAP.get(str(row.event_type or ""))
        if event_class is None or event_class not in routed:
            continue
        entry = routed[event_class]
        items.append({
            "id": row.id,
            "ts": row.created_at.isoformat() if row.created_at else None,
            "event_type": row.event_type,
            "event_class": event_class,
            "class_name": entry["name"],
            "severity": entry["severity"],
            "detail": row.detail,
            "target": row.target_name,
        })
        if len(items) >= bounded:
            break
    return {
        "notifications": items,  # newest first
        "count": len(items),
        "routed_classes": sorted(routed),
        "mapped_event_types": sorted(EVENT_CLASS_MAP),
        "note": (
            "This is the in-app channel delivery: only classes routed to "
            "in-app appear, and the routing above is what gates it. Email, "
            "webhook and SIEM delivery run through the integrations surface. "
            "Emitted event types without a catalog mapping stay in the "
            "events stream, unrouted."
        ),
    }


# Legacy constants retained as import compatibility only; no new drain writes
# the capped event registry. Migration 0096 imports it as unknown tombstones.
DISPATCH_REGISTRY_KEY = "notification.dispatch.v1"
DISPATCH_REGISTRY_CAP = 2000


class DispatchRequest(BaseModel):
    model_config = {"extra": "forbid"}
    limit: int = Field(default=50, ge=1, le=200)  # destination attempts, not events


@router.post("/dispatch")
def dispatch_notifications(
    body: DispatchRequest,
    user: str = Depends(require_roles("superadmin", "admin", "ciso")),
    db: Session = Depends(get_db_session),
):
    """Manually drain durable per-destination receipts (at-least-once).

    Failed/air-gap sends remain retryable. Atomic expiring claims prevent
    ordinary concurrent drains from sharing an attempt; fencing prevents a
    stale owner recording another owner's result. An HTTP ACK followed by a
    process/DB failure is inherently ambiguous: receivers must honour the
    stable Idempotency-Key to deduplicate retries. Never claim exactly-once.
    SMTP and automatic scheduling are not implemented by this endpoint.
    """
    from fastapi import HTTPException
    from control_plane.notification_dispatch import drain_notifications, NotificationPersistenceError

    try:
        summary = drain_notifications(db, limit=body.limit)
    except NotificationPersistenceError:
        raise HTTPException(status_code=503, detail="notification outcome could not be persisted; retry later") from None
    if summary["destination_attempts"]:
        from api.events.platform_events import emit_platform_event

        # All receipt transactions are closed. Retain the operator journal
        # signal without opening a second writer against an uncommitted drain.
        emit_platform_event("notifications.dispatched", target_name="notifications",
                            detail=f"destinations={summary['destination_attempts']} delivered={summary['delivered']} failed={summary['failed']}",
                            payload={key: summary[key] for key in ("destination_attempts", "delivered", "failed", "skipped", "lease_lost")})
    return summary


@router.get("/delivery-summary")
def notification_delivery_summary(
    user: str = Depends(require_roles("superadmin", "admin", "ciso")),
    db: Session = Depends(get_db_session),
):
    """Inspect exact-estate counts without enqueueing, claiming or sending."""
    from control_plane.notification_inspection import receipt_summary

    return receipt_summary(db)


@router.get("/deliveries")
def notification_deliveries(
    limit: int = Query(default=25, ge=1, le=100),
    status: Literal["pending", "inflight", "delivered", "failed", "skipped", "legacy_unknown"] | None = None,
    cursor: str | None = Query(default=None, min_length=1, max_length=512),
    user: str = Depends(require_roles("superadmin", "admin", "ciso")),
    db: Session = Depends(get_db_session),
):
    """Read a bounded metadata-only page; a cursor grants no estate access."""
    from control_plane.notification_inspection import InvalidReceiptCursor, receipt_page

    try:
        return receipt_page(db, limit=limit, status=status, cursor=cursor)
    except InvalidReceiptCursor:
        raise HTTPException(status_code=422, detail="invalid receipt cursor for this estate/filter") from None
