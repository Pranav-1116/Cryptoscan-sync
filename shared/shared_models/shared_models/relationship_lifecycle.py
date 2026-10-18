"""Relationship eligibility, separate from meaning and operational failure.

Missing lifecycle fields retain legacy modeled eligibility, explicitly unbounded.
Expiry is evaluated at a supplied clock; historical snapshots are never mutated.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping

SCHEMA = "cryptoscan.relationship-lifecycle/1"
STATES = frozenset({"ACTIVE", "STALE", "EXPIRED", "DELETED", "SUPERSEDED"})
TERMINAL = frozenset({"DELETED", "SUPERSEDED"})
FIELDS = ("lifecycle_state", "lifecycle_source", "lifecycle_revision", "valid_until",
          "last_confirmed_at", "lifecycle_reason", "lifecycle_evidence_ref",
          "last_reconciliation_id", "projection_state", "record_id")


def utc(value: Any) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise ValueError("invalid lifecycle timestamp")
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def clock() -> datetime:
    return datetime.now(timezone.utc)


def lifecycle_payload(record) -> dict:
    def get(key):
        value = record.get(key) if isinstance(record, Mapping) else getattr(record, key, None)
        if key == "record_id" and value is None:
            value = record.get("id") if isinstance(record, Mapping) else getattr(record, "id", None)
        return value
    return {key: (value.isoformat() if isinstance(value, datetime) else value)
            for key in FIELDS if (value := get(key)) is not None}


def effective_state(record: Mapping, *, now: datetime) -> str:
    state = "ACTIVE" if record.get("lifecycle_state") is None else str(record["lifecycle_state"])
    if state not in STATES:
        return "UNKNOWN"
    if state in TERMINAL:
        return state
    if record.get("valid_until") is not None:
        try:
            if utc(record["valid_until"]) <= utc(now):
                return "EXPIRED"
        except (TypeError, ValueError, OverflowError):
            return "UNKNOWN"
    projection = "ACTIVE" if record.get("projection_state") is None else str(record["projection_state"])
    if projection != "ACTIVE":
        return "STALE" if projection == "STALE" else "UNKNOWN"
    return state


def current(record: Mapping, *, now: datetime) -> bool:
    return effective_state(record, now=now) == "ACTIVE"


def possible(record: Mapping, *, now: datetime) -> bool:
    return effective_state(record, now=now) not in TERMINAL


def summary(records, *, now: datetime) -> dict:
    records = list(records)
    counts = Counter(effective_state(row, now=now) for row in records)
    excluded = [{"id": row.get("id") or row.get("record_id"),
                 "kind": row.get("record_kind"), "state": effective_state(row, now=now),
                 **lifecycle_payload(row)} for row in records if not current(row, now=now)]
    return {"schema": SCHEMA, "as_of": utc(now).isoformat(), "counts": dict(sorted(counts.items())),
            "excluded_count": len(excluded), "excluded_records": excluded[:200],
            "excluded_records_truncated": len(excluded) > 200,
            "unbounded_active_count": sum(current(row, now=now) and row.get("valid_until") is None for row in records),
            "note": "Eligibility changes and zero active links are not evidence of remediation or safety."}


def storage_fields(record: Mapping) -> dict:
    result = lifecycle_payload(record)
    result.setdefault("lifecycle_state", "ACTIVE")
    result.setdefault("projection_state", "ACTIVE")
    expires = result.get("valid_until")
    try:
        epoch = utc(expires).timestamp() if expires is not None else None
    except (ValueError, TypeError, OverflowError):
        epoch = None
        if result["lifecycle_state"] not in TERMINAL:
            result["lifecycle_state"] = "UNKNOWN"
    return {**result, "valid_until_epoch": epoch}


def cypher_current(variable="r") -> str:
    if not variable.isidentifier():
        raise ValueError("invalid Cypher relationship variable")
    return (f"coalesce({variable}.lifecycle_state, 'ACTIVE') = 'ACTIVE' "
            f"AND coalesce({variable}.projection_state, 'ACTIVE') = 'ACTIVE' "
            f"AND ({variable}.valid_until IS NULL OR "
            f"({variable}.valid_until_epoch IS NOT NULL AND {variable}.valid_until_epoch > $lifecycle_as_of))")


def edge_changes(before, after):
    """Diff retained edge assertions, not just structural presence/absence."""
    def index(rows):
        result = {}
        for row in rows:
            key = (str(row.get("from")), str(row.get("to")), str(row.get("label")))
            previous = result.get(key)
            if previous is None or previous.get("lifecycle_revision") is None or (
                    row.get("lifecycle_revision") is not None and row["lifecycle_revision"] >= previous["lifecycle_revision"]):
                result[key] = row
        return result
    old, new = index(before), index(after)
    result = []
    for key in sorted(old.keys() & new.keys()):
        left, right = lifecycle_payload(old[key]), lifecycle_payload(new[key])
        for row, value in ((old[key], left), (new[key], right)):
            value.setdefault("lifecycle_state", "ACTIVE")
            value.setdefault("projection_state", "ACTIVE")
            if row.get("effective_state") is not None:
                value["effective_state"] = row["effective_state"]
        if left != right:
            result.append({"edge": list(key), "before": left, "after": right})
    return result
