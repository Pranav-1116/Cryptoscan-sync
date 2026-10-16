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

from api.dependencies import get_current_user, get_db_session, require_roles
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


# ------------------------------------------------------- outward channel drain
#: Per-tenant dispatch registry: monitor-event ids already sent outward.
#: MonitorEvent ids are UUIDs (no temporal order), so "new" cannot be a
#: high-water cursor — the registry is the exactly-once record. Bounded to
#: the most recent DISPATCH_REGISTRY_CAP dispatched ids.
DISPATCH_REGISTRY_KEY = "notification.dispatch.v1"
DISPATCH_REGISTRY_CAP = 2000

#: Which registered integration kinds each outward channel claims. The two
#: channels PARTITION the integration estate (an endpoint is a webhook
#: receiver whatever its kind), so one notification never double-sends:
#: siem    -> security-ops receivers (siem/soar integrations)
#: webhook -> operational receivers (itsm/cmdb integrations)
CHANNEL_KINDS: dict[str, tuple[str, ...]] = {
    "siem": ("siem", "soar"),
    "webhook": ("itsm", "cmdb"),
}


class DispatchRequest(BaseModel):
    model_config = {"extra": "forbid"}
    limit: int = 50  # max NEW journal events dispatched per drain


@router.post("/dispatch")
def dispatch_notifications(
    body: DispatchRequest,
    user: str = Depends(require_roles("superadmin", "admin", "ciso")),
    db: Session = Depends(get_db_session),
):
    """The OUTWARD channel consumer (§5, round 77) — webhook + SIEM delivery.

    Until now the routing matrix's webhook/SIEM columns were stored but never
    consumed: the delivery engine only fans ``siem.*`` / ``itsm.*`` /
    ``ticket.*`` prefixed events, so a verification outcome routed to SIEM
    never reached a SOC. This endpoint is that missing consumer,
    operator-triggered on the same doctrine as ``/control/deliveries/flush``
    (no background worker fabricates sends):

    - scans the recent monitor-journal window (same over-fetch as the feed)
      for events whose class routes to the webhook or siem channel and that
      are not yet in the per-tenant dispatch registry — each routed
      notification is sent outward exactly once, however often this runs;
    - fans each one to the registered integrations its channel claims, over
      REAL signed HTTP (SSRF-guarded, bounded retries — the same
      ``control_plane.delivery.deliver`` engine the SIEM/ITSM exports use);
    - records every attempt as a ``cp_delivery_logs`` row (the integrations
      console delivery audit) and stamps each integration's sync status.

    Honest scope: the EMAIL channel is routing configuration only — no SMTP
    transport is wired in this deployment, so email-routed classes are
    counted here and never claimed sent. Emitted event types without a
    catalog mapping are not force-fit; they stay in the events stream,
    unrouted. Events older than the fetch window are not retro-dispatched
    (the same window honesty the feed documents) — drain regularly.
    """
    from control_plane.delivery import deliver
    from db.models.monitor import MonitorEvent
    from db.repositories.control_plane_repository import ControlPlaneRepository
    from db.repositories.enterprise_repository import EnterpriseRepository

    merged, _persisted = _merged(db)
    outward = {
        entry["id"]: entry
        for entry in merged
        if entry["channels"].get("webhook") or entry["channels"].get("siem")
    }

    settings = _repo(db)
    registry = settings.get(DISPATCH_REGISTRY_KEY, default={}) or {}
    known: list = list(registry.get("dispatched", []))
    known_set = {str(i) for i in known}

    bounded = max(1, min(int(body.limit or 50), 200))
    window = (
        db.query(MonitorEvent)
        .order_by(MonitorEvent.created_at.desc(), MonitorEvent.id.desc())
        .limit(bounded * 3)  # over-fetch: already-dispatched / unmapped /
        .all()               # routed-off rows occupy the window
    )
    rows = list(reversed(window))  # oldest-first dispatch order

    ent = EnterpriseRepository(db)
    integrations = [i.to_dict() for i in ent.list_integrations()]
    by_channel = {
        channel: [
            i for i in integrations
            if i.get("enabled", True) and i.get("kind") in kinds
        ]
        for channel, kinds in CHANNEL_KINDS.items()
    }

    cp = ControlPlaneRepository(db)
    attempts: list[dict] = []
    status_counts: dict[str, int] = {}
    email_routed = 0
    considered = 0

    for row in rows:
        if str(row.id) in known_set:
            continue  # already sent outward exactly once
        event_class = EVENT_CLASS_MAP.get(str(row.event_type or ""))
        if event_class is None or event_class not in outward:
            continue  # in the window but not routed outward (no side effects)
        considered += 1
        known.append(str(row.id))
        known_set.add(str(row.id))
        entry = outward[event_class]
        if entry["channels"].get("email"):
            email_routed += 1  # counted, never claimed sent — no transport yet

        channels_on = [c for c in ("siem", "webhook") if entry["channels"].get(c)]
        targets = [i for c in channels_on for i in by_channel[c]]
        envelope = {
            "id": row.id,
            "event_type": f"notification.{event_class}",
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "payload": {
                "event_type": row.event_type,
                "event_class": event_class,
                "class_name": entry["name"],
                "severity": entry["severity"],
                "detail": row.detail,
                "target": row.target_name,
                "monitor_event_id": row.id,
            },
        }
        results = []
        for integ in targets:
            result = deliver(integ, envelope, sleep=lambda _s: None, max_attempts=2)
            rd = result.to_dict()
            results.append(rd)
            status_counts[rd["status"]] = status_counts.get(rd["status"], 0) + 1
            cp.record_delivery(result=rd, event_type=envelope["event_type"],
                               event_id=str(row.id))
            ent.mark_integration_synced(integ["id"], rd["status"])
        attempts.append({
            "monitor_event_id": row.id,
            "event_type": row.event_type,
            "event_class": event_class,
            "channels": channels_on,
            "results": results,
        })

    settings.set(
        DISPATCH_REGISTRY_KEY,
        {"dispatched": known[-DISPATCH_REGISTRY_CAP:]},
        updated_by=user,
    )

    dispatched = len(attempts)
    db.commit()  # close the write transaction before the journal emit below

    from api.events.platform_events import emit_platform_event

    emit_platform_event(
        "notifications.dispatched",
        detail=(f"examined={considered} dispatched={dispatched} "
                f"delivered={status_counts.get('delivered', 0)}"),
        target_name="notifications",
        payload={"examined": considered, "dispatched": dispatched,
                 "delivered": status_counts.get("delivered", 0),
                 "failed": status_counts.get("failed", 0),
                 "email_routed": email_routed},
    )
    return {
        "ok": True,
        "window": len(window),
        "examined": considered,
        "dispatched": dispatched,
        "registry_size": min(len(known), DISPATCH_REGISTRY_CAP),
        "delivered": status_counts.get("delivered", 0),
        "failed": status_counts.get("failed", 0),
        "skipped": status_counts.get("skipped", 0),
        "email_routed": email_routed,
        "integrations": {c: len(v) for c, v in by_channel.items()},
        "attempts": attempts,
        "note": (
            "Operator-triggered outward drain: each routed notification is "
            "sent outward exactly once per tenant (dispatch registry), "
            "however often this runs. The siem channel delivers to "
            "registered SIEM/SOAR integrations, the webhook channel to "
            "ITSM/CMDB receivers — over real signed HTTP, every attempt "
            "audited in the integrations delivery log. Email routing is "
            "stored but no SMTP transport is wired in this deployment; "
            "nothing is claimed sent. Unmapped event types are never "
            "force-fit, and events older than the fetch window are not "
            "retro-dispatched."
        ),
    }
