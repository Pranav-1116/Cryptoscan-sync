"""Durable, tenant-exact, per-destination notification drain.

Transactions are owned here: enqueue/claim commits BEFORE network I/O; receipt,
transport audit and integration status commit together AFTER it. Do not call
inside an unrelated write transaction. HTTP ACK -> process/DB crash remains
ambiguous; delivery is at-least-once, never exactly-once. Receivers must honour
the stable Idempotency-Key for deduplication across that ambiguity.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from types import SimpleNamespace
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, case, exists, func, or_, select, update

from control_plane.notification_routing import CHANNEL_KINDS, EVENT_CLASS_MAP, merged_routing
from db.models.app_setting import AppSetting
from db.models.enterprise import Integration
from db.models.monitor import MonitorEvent
from db.models.notification_delivery import NotificationDelivery as Receipt
from db.tenancy import current_tenant

logger = logging.getLogger(__name__)

LEASE_SECONDS = 120
LEGACY_KEY = "notification.dispatch.v1"


class NotificationPersistenceError(RuntimeError):
    """No durable outcome can be promised; abort without a success response."""


def scope_key(owner: str | None) -> str:
    return "platform" if owner is None else f"tenant:{owner}"


def delivery_identity(owner, event_id, integration_id, channel) -> tuple[str, str]:
    encoded = json.dumps([scope_key(owner), event_id, integration_id, channel], separators=(",", ":")).encode()
    key = hashlib.sha256(encoded).hexdigest()
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "cryptoscan.notification:" + key)), key


def _insert(session, **values):
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    elif dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        raise RuntimeError("notification receipts require SQLite or PostgreSQL atomic upserts")
    # A unique per-destination identity, not a capped in-memory/JSON registry.
    return session.execute(insert(Receipt).values(**values).on_conflict_do_nothing()).rowcount


def _values(owner, event_id, integration_id, channel, event_class, envelope, now, *, status="pending"):
    identity, key = delivery_identity(owner, event_id, integration_id, channel)
    return dict(id=identity, delivery_key=key, scope_key=scope_key(owner), tenant_id=owner,
                event_id=event_id, integration_id=integration_id, channel=channel,
                event_class=event_class, envelope=envelope, status=status, attempt_count=0,
                next_attempt_at=now)


def _import_legacy_registry(session, owner, now):
    """Also protects create_all development databases; never invent past ACKs.

    Production migration 0096 additionally imports observed successful delivery
    audit rows (including entries evicted from the old JSON registry). Upgrade
    existing datasets before using the new drain; mixed old/new writers are not
    a supported rolling-deployment mode.
    """
    row = session.execute(select(AppSetting).where(
        AppSetting.key == LEGACY_KEY, AppSetting.tenant_id == owner)).scalar_one_or_none()
    if row is None:
        return
    value = json.loads(row.value)
    ids = value.get("dispatched") if isinstance(value, dict) else None
    if not isinstance(ids, list) or len(ids) > 2000 or any(
        not isinstance(i, str) or not 1 <= len(i) <= 36 for i in ids
    ):
        raise ValueError("invalid legacy notification dispatch registry; operator reconciliation required")
    known = set(session.execute(select(Receipt.event_id).where(
        Receipt.scope_key == scope_key(owner), Receipt.channel == "legacy")).scalars())
    for event_id in set(ids) - known:
        _insert(session, **_values(owner, event_id, "legacy-registry", "legacy", "", {}, now,
                                  status="legacy_unknown"))


def _routed(session):
    routing, _ = merged_routing(session)
    return {entry["id"]: entry for entry in routing}


def _eligibility(routing, *, receipt=False):
    branches = []
    for channel, kinds in CHANNEL_KINDS.items():
        classes = [entry["id"] for entry in routing.values() if entry["channels"].get(channel)]
        if receipt:
            event_filter = and_(Receipt.channel == channel, Receipt.event_class.in_(classes))
        else:
            types = [etype for etype, cls in EVENT_CLASS_MAP.items() if cls in classes]
            event_filter = MonitorEvent.event_type.in_(types)
        branches.append(and_(Integration.kind.in_(kinds), event_filter))
    return or_(*branches)


def _enqueue(session, owner, routing, now, limit):
    channel = case((Integration.kind.in_(CHANNEL_KINDS["siem"]), "siem"), else_="webhook")
    registered = exists(select(Receipt.id).where(
        Receipt.scope_key == scope_key(owner), Receipt.event_id == MonitorEvent.id,
        or_(Receipt.channel == "legacy", and_(Receipt.integration_id == Integration.id, Receipt.channel == channel)),
    ).correlate(MonitorEvent, Integration))
    # Filter BEFORE LIMIT; mapped events cannot be starved by unrelated/newer
    # traffic, old completed receipts or another tenant. No temporal UUID cursor.
    pairs = session.execute(select(MonitorEvent, Integration).join(
        Integration, Integration.tenant_id == owner).where(
            MonitorEvent.tenant_id == owner, Integration.enabled.is_(True),
            _eligibility(routing), ~registered,
        ).order_by(MonitorEvent.created_at, MonitorEvent.id, Integration.id).limit(limit)).all()
    for event, integration in pairs:
        event_class = EVENT_CLASS_MAP[event.event_type]
        entry = routing[event_class]
        channel_name = "siem" if integration.kind in CHANNEL_KINDS["siem"] else "webhook"
        envelope = {"id": event.id, "event_type": f"notification.{event_class}",
                    "created_at": event.created_at.isoformat() if event.created_at else now.isoformat(),
                    "payload": {"event_type": event.event_type, "event_class": event_class,
                                "class_name": entry["name"], "severity": entry["severity"],
                                "detail": (event.detail or "")[:2000], "target": event.target_name, "monitor_event_id": event.id}}
        _insert(session, **_values(owner, event.id, integration.id, channel_name, event_class, envelope, now))
    return len(pairs)


def claim(session, identity, *, now, token=None):
    """Atomic per-pair lease, committed before any caller may perform I/O."""
    token = token or str(uuid.uuid4())
    owner = current_tenant()
    due = or_(and_(Receipt.status.in_(("pending", "failed", "skipped")), Receipt.next_attempt_at <= now),
              and_(Receipt.status == "inflight", Receipt.lease_until <= now))
    claimed = session.execute(update(Receipt).where(
        Receipt.id == identity, Receipt.scope_key == scope_key(owner), Receipt.tenant_id == owner, due,
    ).values(status="inflight", lease_token=token, lease_until=now + timedelta(seconds=LEASE_SECONDS),
             attempt_count=Receipt.attempt_count + 1).returning(Receipt.id).execution_options(synchronize_session=False)).scalar_one_or_none()
    session.commit()
    return token if claimed else None


def _finish(session, receipt, token, result, now):
    from db.repositories.control_plane_repository import ControlPlaneRepository

    status = result["status"]
    delay = min(60 * (2 ** min(max(receipt.attempt_count - 1, 0), 6)), 3600)
    changed = session.execute(update(Receipt).where(
        Receipt.id == receipt.id, Receipt.scope_key == scope_key(current_tenant()),
        Receipt.tenant_id == current_tenant(), Receipt.status == "inflight", Receipt.lease_token == token,
    ).values(status=status, lease_token=None, lease_until=None,
             next_attempt_at=now + timedelta(seconds=delay),
             last_error=(result.get("error") or "")[:300] or None, http_status=result.get("http_status"),
             delivered_at=now if status == "delivered" else None).returning(Receipt.id).execution_options(synchronize_session=False)).scalar_one_or_none()
    # An actual stale-owner HTTP attempt is still audit evidence, even when its
    # token lost the receipt fence. It must not overwrite the new owner.
    ControlPlaneRepository(session).record_delivery(
        result=result, event_type=receipt.envelope["event_type"], event_id=receipt.event_id,
        tenant_id=current_tenant())
    if changed:
        session.execute(update(Integration).where(
            Integration.id == receipt.integration_id, Integration.tenant_id == current_tenant(),
        ).values(last_sync_status=status, last_sync_at=now.isoformat()))
    session.commit()
    return bool(changed)


def drain_notifications(session, *, limit=50, clock=None, transport=None, budget_s=20.0, should_stop=None):
    """Bounded manual drain. limit counts destinations, not distinct events.

    budget_s is a soft dispatch-loop budget, NOT a hard DNS/HTTP deadline.
    Transport uses one bounded HTTP attempt per claim, no sleeps; persistent
    exponential backoff is 60s..1h. Automatic retries require the separate opt-in notification scheduler.
    """
    from control_plane.delivery import DeliveryResult, deliver

    owner = current_tenant()
    limit = max(1, min(int(limit), 200))
    clock = clock or (lambda: datetime.now(timezone.utc))
    transport = transport or deliver
    deadline = time.monotonic() + budget_s
    groups = {}
    counts = Counter()
    enqueued = 0
    try:
        now = clock()
        routing = _routed(session)
        _import_legacy_registry(session, owner, now)
        enqueued = _enqueue(session, owner, routing, now, limit)
        session.commit()
        due = or_(and_(Receipt.status.in_(("pending", "failed", "skipped")), Receipt.next_attempt_at <= now),
                  and_(Receipt.status == "inflight", Receipt.lease_until <= now))
        identities = list(session.execute(select(Receipt.id).join(Integration, and_(
            Integration.id == Receipt.integration_id, Integration.tenant_id == owner,
        )).where(Receipt.scope_key == scope_key(owner), Receipt.tenant_id == owner,
                 Integration.enabled.is_(True), _eligibility(routing, receipt=True), due,
        ).order_by(Receipt.next_attempt_at, Receipt.created_at, Receipt.id).limit(limit)).scalars())
        session.commit()  # release read transaction before claims/network
        for identity in identities:
            if time.monotonic() >= deadline or (should_stop is not None and should_stop()):
                break
            # Re-read routing + destination at claim time; paused channels and
            # disabled destinations are not permanently acknowledged.
            routing = _routed(session)
            pair = session.execute(select(Receipt, Integration).join(Integration, and_(
                Integration.id == Receipt.integration_id, Integration.tenant_id == owner,
            )).where(Receipt.id == identity, Receipt.scope_key == scope_key(owner), Receipt.tenant_id == owner,
                     Integration.enabled.is_(True), _eligibility(routing, receipt=True))).first()
            if pair is None:
                session.commit()
                continue
            receipt, integration = pair
            destination = integration.to_dict()
            token = claim(session, identity, now=clock())
            if token is None:
                continue
            # Refresh after commit so the attempt counter/envelope reflect this
            # claim, not stale session identity-map values from discovery.
            session.refresh(receipt)
            lease_until = receipt.lease_until.replace(tzinfo=timezone.utc) if receipt.lease_until.tzinfo is None else receipt.lease_until
            if receipt.lease_token != token or receipt.status != "inflight" or lease_until <= clock():
                session.commit()
                counts["lease_lost"] += 1
                continue
            snapshot = {name: getattr(receipt, name) for name in (
                "id", "integration_id", "event_id", "event_class", "channel", "delivery_key", "attempt_count", "envelope")}
            session.commit()  # no read/write transaction held across network I/O
            receipt = SimpleNamespace(**snapshot)
            if should_stop is not None and should_stop():
                # The claim stays durable and recovers after lease expiry; do
                # not start new I/O once shutdown has been observed.
                break
            try:
                result = transport(destination, receipt.envelope, max_attempts=1, timeout=10.0,
                                   idempotency_key=receipt.delivery_key).to_dict()
                if result["status"] not in {"delivered", "failed", "skipped"} or (
                    result["status"] == "delivered" and not 200 <= (result.get("http_status") or 0) < 300
                ):
                    raise ValueError("invalid transport outcome")
            except Exception as exc:
                # Do not repeat network/config/source/credential exception text.
                result = DeliveryResult(integration_id=receipt.integration_id,
                                        provider=destination["provider"], kind=destination["kind"],
                                        endpoint=destination.get("endpoint") or "", status="failed",
                                        error=f"transport error ({type(exc).__name__})").to_dict()
            persisted = _finish(session, receipt, token, result, clock())
            if not persisted:
                counts["lease_lost"] += 1
            else:
                counts[result["status"]] += 1
            group = groups.setdefault(receipt.event_id, {
                "monitor_event_id": receipt.event_id, "event_type": receipt.envelope["payload"]["event_type"],
                "event_class": receipt.event_class, "channels": [], "results": [],
            })
            if receipt.channel not in group["channels"]:
                group["channels"].append(receipt.channel)
            group["results"].append({**result, "receipt_id": identity, "recorded": persisted})
        statuses = dict(session.execute(select(Receipt.status, func.count()).where(
            Receipt.scope_key == scope_key(owner), Receipt.tenant_id == owner,
        ).group_by(Receipt.status)).all())
        integration_counts = {channel: session.scalar(select(func.count()).select_from(Integration).where(
            Integration.tenant_id == owner, Integration.enabled.is_(True), Integration.kind.in_(kinds)))
            for channel, kinds in CHANNEL_KINDS.items()}
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("notification_drain_unconfirmed", extra={"error_type": type(exc).__name__})
        # No success response if receipt/audit persistence failed, particularly
        # after a possible ACK. Its committed lease will expire and retry.
        raise NotificationPersistenceError("notification drain did not establish a durable outcome") from exc
    return {"ok": counts["lease_lost"] == 0, "window": enqueued, "enqueued": enqueued,
            "examined": len(groups), "dispatched": len(groups), "destination_attempts": sum(len(g["results"]) for g in groups.values()),
            "registry_size": sum(statuses.values()), "receipts": statuses,
            "delivered": counts["delivered"], "failed": counts["failed"], "skipped": counts["skipped"],
            "lease_lost": counts["lease_lost"], "email_routed": sum(
                bool(routing[g["event_class"]]["channels"].get("email")) for g in groups.values()),
            "integrations": integration_counts, "attempts": list(groups.values()),
            "note": "Manual at-least-once drain with durable per-destination receipts and expiring fenced claims. "
                    "Failed/air-gap outcomes remain retryable after backoff; automatic drains require the separate opt-in scheduler. "
                    "Receivers must honour Idempotency-Key to deduplicate ambiguous ACK/crash retries. "
                    "Legacy event-only registry entries are suppressed as unknown, never labelled delivered. "
                    "Email is count-only: no SMTP transport is wired. No attempt does not mean all events delivered."}
