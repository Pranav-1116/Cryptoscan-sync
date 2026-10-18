"""Read-only, exact-estate receipt diagnostics. Never enqueue, claim or send.

An explicit column projection excludes envelopes, transport errors, endpoints,
lease tokens and delivery keys. Cursors are navigation hints, not authorization.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from sqlalchemy import String, and_, case, func, or_, select, type_coerce

from control_plane.notification_dispatch import scope_key
from db.models.notification_delivery import NotificationDelivery as Receipt
from db.tenancy import current_tenant

STATUSES = ("pending", "inflight", "delivered", "failed", "skipped", "legacy_unknown")
PENDING = ("pending", "inflight", "failed", "skipped")


class InvalidReceiptCursor(ValueError):
    pass


def _utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _iso(value):
    return _utc(value).isoformat() if value is not None else None


def _estate():
    owner = current_tenant()
    # ORM NULL readability is not operational estate authority.
    return and_(Receipt.tenant_id == owner, Receipt.scope_key == scope_key(owner))


def _due(now):
    return or_(and_(Receipt.status.in_(("pending", "failed", "skipped")), Receipt.next_attempt_at <= now),
               and_(Receipt.status == "inflight", Receipt.lease_until <= now))


def receipt_summary(session, *, now=None):
    now = now or datetime.now(timezone.utc)
    rows = session.execute(select(Receipt.status, func.count(),
                                  func.sum(case((_due(now), 1), else_=0)), func.min(Receipt.created_at))
                           .where(_estate()).group_by(Receipt.status).execution_options(autoflush=False)).all()
    counts = dict.fromkeys(STATUSES, 0)
    due = expired = 0
    oldest = []
    for status, count, eligible, created in rows:
        counts[status] = count
        due += int(eligible or 0)
        if status == "inflight":
            expired += int(eligible or 0)
        if status in PENDING and created is not None:
            oldest.append(_utc(created))
    return {"observed_at": _iso(now), "counts": counts, "total": sum(counts.values()),
            "pending": sum(counts[status] for status in PENDING), "time_eligible": due,
            "expired_claims": expired, "oldest_pending_at": _iso(min(oldest)) if oldest else None,
            "note": "Receipt counts only, not event counts, scheduler liveness or receiver ingestion. "
                    "Time-eligible receipts may still be deferred by routing or destination eligibility. "
                    "Legacy unknown is suppressed history, not delivered. Empty does not prove delivery completeness."}


def _decode(cursor, status):
    try:
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 512:
            raise ValueError()
        raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        body = json.loads(raw)
        if not isinstance(body, dict) or set(body) != {"v", "scope", "status", "at", "id"}:
            raise ValueError()
        if type(body["v"]) is not int or body["v"] != 1 or body["scope"] != scope_key(current_tenant()) or body["status"] != status:
            raise ValueError()
        if (not isinstance(body["id"], str) or not 1 <= len(body["id"]) <= 36
                or not body["id"].isascii() or any(not (char.isalnum() or char in "-_") for char in body["id"])):
            raise ValueError()
        at = datetime.fromisoformat(body["at"])
        if at.tzinfo is None:
            raise ValueError()
        return _utc(at), body["id"]
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        raise InvalidReceiptCursor("invalid receipt cursor for this estate/filter") from None


def receipt_page(session, *, limit=25, status=None, cursor=None, now=None):
    if type(limit) is not int or not 1 <= limit <= 100 or (status is not None and status not in STATUSES):
        raise ValueError("invalid receipt page options")
    now = now or datetime.now(timezone.utc)
    query = select(Receipt.id, Receipt.event_id, Receipt.integration_id, Receipt.channel, Receipt.event_class,
                   Receipt.status, Receipt.attempt_count, Receipt.created_at, Receipt.next_attempt_at,
                   Receipt.lease_until, Receipt.delivered_at, Receipt.http_status,
                   and_(Receipt.last_error.is_not(None), Receipt.last_error != "").label("has_error"),
                   _due(now).label("time_eligible")).where(_estate())
    if status is not None:
        query = query.where(Receipt.status == status)
    if cursor is not None:
        at, identity = _decode(cursor, status)
        sort_column = Receipt.created_at
        if session.get_bind().dialect.name == "sqlite":
            # SQLite server defaults omit fractional seconds, while SQLAlchemy
            # binds datetimes with .000000. Comparing those text spellings can
            # repeat the anchor forever. Recover its exact stored spelling in
            # this estate, without reading an envelope or flushing caller work.
            sort_column = type_coerce(Receipt.created_at, String)
            at = session.execute(select(sort_column).where(_estate(), Receipt.id == identity)
                                 .execution_options(autoflush=False)).scalar_one_or_none()
            if at is None:
                raise InvalidReceiptCursor("receipt cursor anchor unavailable; refresh this estate/filter")
        query = query.where(or_(sort_column < at, and_(sort_column == at, Receipt.id < identity)))
    rows = session.execute(query.order_by(Receipt.created_at.desc(), Receipt.id.desc()).limit(limit + 1).execution_options(autoflush=False)).mappings().all()
    items = []
    for row in rows[:limit]:
        items.append({name: row[name] for name in (
            "id", "event_id", "integration_id", "channel", "event_class", "status", "attempt_count", "http_status")}
                     | {"created_at": _iso(row["created_at"]), "delivered_at": _iso(row["delivered_at"]),
                        "next_attempt_at": _iso(row["next_attempt_at"]) if row["status"] in ("pending", "failed", "skipped") else None,
                        "lease_expires_at": _iso(row["lease_until"]) if row["status"] == "inflight" else None,
                        "has_error": bool(row["has_error"]), "time_eligible": bool(row["time_eligible"])})
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        body = {"v": 1, "scope": scope_key(current_tenant()), "status": status,
                "at": _iso(last["created_at"]), "id": last["id"]}
        next_cursor = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode().rstrip("=")
    return {"items": items, "next_cursor": next_cursor, "observed_at": _iso(now),
            "note": "Read-only receipt metadata; payloads, endpoints, errors and claim credentials are omitted. "
                    "Newest-created first. Pagination is not a snapshot: concurrent status changes can move rows between filters. "
                    "HTTP acknowledgement is not downstream ingestion; no redrive is performed."}
