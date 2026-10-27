"""Versioned, owner-bound replay cursors and retained per-estate pages.

Completeness is relative to a frozen retained-journal snapshot, never all historic
scans. Epoch reset, missing entries and retention loss are explicit, not empty
success. Local memory is not a durable backend.
"""

import base64
from collections import deque
from copy import deepcopy
import hashlib
import json
import threading
import uuid


class ReplayError(ValueError):
    pass


def bucket(owner):
    if owner is not None and (not isinstance(owner, str) or not owner):
        raise ReplayError("Invalid estate owner")
    return hashlib.sha256(json.dumps([owner], separators=(",", ":")).encode()).hexdigest()


def cursor_for(owner, epoch, after, through=None):
    raw = json.dumps([1, bucket(owner), epoch, after, through], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(owner, cursor):
    if not cursor:
        return None, 0, None
    try:
        if not isinstance(cursor, str) or len(cursor) > 1024:
            raise ValueError()
        version, scope, epoch, after, through = json.loads(
            base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        )
        if (
            version != 1
            or scope != bucket(owner)
            or (epoch is not None and (not isinstance(epoch, str) or len(epoch) != 32))
        ):
            raise ValueError()
        if (
            type(after) is not int
            or not 0 <= after < 2**63
            or (through is not None and (type(through) is not int or not after <= through < 2**63))
        ):
            raise ValueError()
        return epoch, after, through
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ReplayError("Invalid or foreign estate replay cursor") from exc


def replay_page(provider, owner, cursor=None, limit=100, *, durable=False):
    epoch, after, through = decode_cursor(owner, cursor)
    page = provider(owner, after, through, max(1, min(int(limit), 500)))
    current, oldest, latest, end, records = page
    if epoch is not None and epoch != current:
        raise ReplayError("Estate replay epoch changed; explicit resynchronization required")
    if after > latest or (through is not None and through > latest):
        raise ReplayError("Replay cursor is ahead of this journal")
    gap = after < oldest - 1
    # Read one look-ahead record; each page advances in ascending estate order.
    size = max(1, min(int(limit), 500))
    more = len(records) > size
    records = records[:size]
    start = max(after + 1, oldest)
    expected = min(size + int(more), max(0, end - start + 1))
    if len(page[4]) != expected:
        raise ReplayError("Estate journal is incomplete or corrupt")
    for position, (sequence, frame) in enumerate(page[4], start):
        if (
            sequence != position
            or frame.get("tenant_id") != owner
            or frame.get("estate_sequence") != sequence
            or frame.get("estate_epoch") != current
        ):
            raise ReplayError("Estate journal ownership/sequence mismatch")
        payload = frame.get("payload") or {}
        if not isinstance(payload, dict) or (payload.get("tenant_id") is not None and payload["tenant_id"] != owner):
            raise ReplayError("Estate journal has conflicting owner metadata")
    # Public identity is estate-local; leaking a shared numeric ID would let
    # clients infer foreign traffic from the gaps between their own events.
    # Transport node/global IDs stay in the internal journal only.
    fields = ("ts", "type", "source", "payload", "tenant_id", "estate_sequence", "estate_epoch")
    events = [
        {
            **{key: frame[key] for key in fields if key in frame},
            "id": sequence,
            "replay_cursor": cursor_for(owner, current, sequence),
        }
        for sequence, frame in records
    ]
    after_page = records[-1][0] if more else end
    return {
        "events": events,
        "next_cursor": cursor_for(owner, current, after_page, end if more else None),
        "has_more": more,
        "complete": not more and not gap,
        "retention_gap": gap,
        "epoch": current,
        "oldest_sequence": oldest,
        "latest_sequence": latest,
        "snapshot_through": end,
        "durable": durable,
        "coverage": "RETAINED_ESTATE_SNAPSHOT",
        "historical_backfill": False,
    }


class MemoryEstateJournal:
    def __init__(self, retention=500):
        self.retention = retention
        self._partitions = {}
        self._lock = threading.RLock()

    def append(self, frame):
        with self._lock:
            key = bucket(frame.get("tenant_id"))
            epoch, latest, rows = self._partitions.get(key, (uuid.uuid4().hex, 0, deque(maxlen=self.retention)))
            latest += 1
            frame.update(estate_sequence=latest, estate_epoch=epoch)
            rows.append((latest, deepcopy(frame)))
            self._partitions[key] = (epoch, latest, rows)

    def page(self, owner, after, through, limit):
        with self._lock:
            epoch, latest, rows = self._partitions.get(bucket(owner), (None, 0, []))
            oldest = rows[0][0] if rows else 1
            end = latest if through is None else through
            records = [(seq, deepcopy(frame)) for seq, frame in rows if after < seq <= end][: limit + 1]
            return epoch, oldest, latest, end, records
