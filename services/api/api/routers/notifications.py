"""Notification routing preferences (spec §37).

Persists the per-tenant event-class -> channel routing (in-app / email /
webhook / SIEM) chosen in the console. Stored as an AppSetting (JSON) so the
routing survives restarts and is read by the delivery layer. No secrets here —
channel destinations are configured separately under /enterprise/integrations.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.settings_repository import SettingsRepository

router = APIRouter(prefix="/notifications", tags=["notifications"])

ROUTING_SETTING_KEY = "notification.routing.v1"

#: Canonical event-class catalog the console exposes. ids/names/severity are
#: product config served live by the control plane; only the per-channel
#: boolean routing map is persisted per tenant (overlaid on these defaults).
CHANNELS = ("inApp", "email", "webhook", "siem")


def _ev(id_: str, name: str, severity: str, channels: dict[str, bool]) -> dict:
    return {"id": id_, "name": name, "severity": severity,
            "channels": {c: bool(channels.get(c, False)) for c in CHANNELS}}


CATALOG: list[dict] = [
    _ev("critical_crypto_change", "Critical crypto change", "CRITICAL",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("new_asset", "New asset discovered", "LOW",
        {"inApp": True, "email": False, "webhook": False, "siem": True}),
    _ev("new_certificate", "New certificate", "MEDIUM",
        {"inApp": True, "email": True, "webhook": False, "siem": True}),
    _ev("pqc_risk_change", "PQC risk change", "HIGH",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("crypto_drift", "Crypto drift", "HIGH",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("scanner_failure", "Scanner failure", "CRITICAL",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("cloud_change", "Cloud change", "MEDIUM",
        {"inApp": True, "email": False, "webhook": True, "siem": True}),
    _ev("vendor_change", "Vendor change", "MEDIUM",
        {"inApp": True, "email": False, "webhook": False, "siem": False}),
    _ev("hardware_change", "Hardware change", "MEDIUM",
        {"inApp": True, "email": False, "webhook": True, "siem": True}),
    _ev("compliance_failure", "Compliance failure", "HIGH",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    # §5 (round 76): verification outcomes are now a routable class —
    # VERIFIED / PARTIAL / FAILED / REGRESSION / INCONCLUSIVE land in the
    # in-app feed (GET /notifications/feed) and can be routed outward.
    _ev("remediation_verification", "Remediation verification outcome", "HIGH",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("remediation_task", "Remediation task lifecycle", "MEDIUM",
        {"inApp": True, "email": False, "webhook": False, "siem": False}),
]

#: emitted platform event_type → catalog class id. Only defensible pairs
#: are mapped — an emitted type with no entry here is NOT force-fit into
#: a class; it stays visible in the events stream, just unrouted. This
#: map is the single authority the in-app feed consults.
EVENT_CLASS_MAP = {
    "remediation.task_verified": "remediation_verification",
    "remediation.task_created": "remediation_task",
    "remediation.task_accepted": "remediation_task",
    "remediation.task_completed": "remediation_task",
    "remediation.drift_tasks_created": "remediation_task",
    "evidence.chain_broken": "compliance_failure",
}


class RoutingItem(BaseModel):
    id: str
    name: str
    severity: str = "INFO"
    channels: dict[str, bool] = Field(default_factory=dict)


class RoutingPayload(BaseModel):
    routing: list[RoutingItem]


def _repo(db: Session) -> SettingsRepository:
    return SettingsRepository(db)


def _merged(db: Session) -> tuple[list[dict], bool]:
    """Catalog defaults with per-tenant persisted channel overrides overlaid."""
    data = _repo(db).get(ROUTING_SETTING_KEY, default=[])
    persisted = data if isinstance(data, list) else []
    by_id = {item.get("id"): item for item in persisted if isinstance(item, dict)}
    merged = []
    for entry in CATALOG:
        override = by_id.get(entry["id"])
        channels = dict(entry["channels"])
        if override and isinstance(override.get("channels"), dict):
            for c in CHANNELS:
                if c in override["channels"]:
                    channels[c] = bool(override["channels"][c])
        merged.append({**entry, "channels": channels})
    # include any persisted classes not in the current catalog (forward-safe)
    known = {e["id"] for e in CATALOG}
    for item in persisted:
        if isinstance(item, dict) and item.get("id") not in known:
            merged.append({"id": item["id"], "name": item.get("name", item["id"]),
                           "severity": item.get("severity", "INFO"),
                           "channels": {c: bool(item.get("channels", {}).get(c, False)) for c in CHANNELS}})
    return merged, bool(persisted)


@router.get("/catalog")
def get_catalog(user: str = Depends(get_current_user)):
    """The canonical event-class catalog with default channel routing."""
    return {"catalog": CATALOG, "channels": list(CHANNELS)}


@router.get("/routing")
def get_routing(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    merged, persisted = _merged(db)
    return {"routing": merged, "persisted": persisted}


@router.put("/routing")
def put_routing(body: RoutingPayload, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
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
    _repo(db).set(ROUTING_SETTING_KEY, cleaned, updated_by=user)
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

    merged, _persisted = _merged(db)
    routed = {entry["id"]: entry for entry in merged if entry["channels"].get("inApp")}

    bounded = max(1, min(int(limit or 50), 200))
    rows = (
        db.query(MonitorEvent)
        .order_by(MonitorEvent.created_at.desc(), MonitorEvent.id.desc())
        .limit(bounded * 3)  # over-fetch: unmapped/routed-off rows are filtered
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
