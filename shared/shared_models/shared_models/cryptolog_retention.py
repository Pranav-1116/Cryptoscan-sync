"""CryptoLog retention planning (docs/cryptolog/01_PRODUCT_SPEC.md §10, §7).

A plan is a PROJECTION: it names what retention would archive or mark for
deletion, with reasons — it never performs either. Execution is a
separate, disposition-gated act; a deletion is never silent, and an
original event is never modified. Deterministic: same inputs, same plan.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence


RETAIN = "RETAIN"
ARCHIVE = "ARCHIVE"
DELETE_CANDIDATE = "DELETE_CANDIDATE"

#: retention classes by logging kind: configuration changes and audit
#: records are long-lived by default; activity events are shorter.
RETENTION_CLASSES = ("SHORT", "LONG", "PERMANENT")

DEFAULT_POLICY: dict[str, Any] = {
    "schema": "cryptoscan.cryptolog-retention/1",
    "activity_retention_days": 180,
    "change_retention_days": 3650,
    "audit_retention_days": 3650,
    "archive_after_days": 90,
    "require_disposition_ref": True,
}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def retention_class(event: Mapping[str, Any]) -> str:
    kind = _clean(event.get("logging_kind")).upper()
    if kind == "AUDIT":
        return "PERMANENT"
    if kind == "CHANGE":
        return "LONG"
    return "SHORT"


def _retention_days(policy: Mapping[str, Any], event: Mapping[str, Any]) -> int:
    kind = _clean(event.get("logging_kind")).upper()
    if kind == "AUDIT":
        return int(policy["audit_retention_days"])
    if kind == "CHANGE":
        return int(policy["change_retention_days"])
    return int(policy["activity_retention_days"])


def _observed(event: Mapping[str, Any]) -> str:
    obs = event.get("observation") or {}
    return _clean(event.get("observed") or obs.get("observed_at") or "")


def plan(events: Sequence[Mapping[str, Any]], policy: Mapping[str, Any],
         now: datetime) -> dict[str, Any]:
    """Project retention actions over recorded events. Nothing is changed:
    every row says what WOULD happen and why, and DELETE_CANDIDATE is the
    strongest claim the plan ever makes — deletion needs a named
    disposition, and this module never performs one."""
    policy = {**DEFAULT_POLICY, **dict(policy or {})}
    rows: list[dict[str, Any]] = []
    counts = {RETAIN: 0, ARCHIVE: 0, DELETE_CANDIDATE: 0}
    for event in events:
        observed = _observed(event)
        age_days = None
        if observed:
            try:
                age_days = (now - datetime.fromisoformat(
                    observed.replace("Z", "+00:00"))).days
            except ValueError:
                age_days = None
        if age_days is None:
            action, reason = RETAIN, (
                "no parseable observation time: age is unknown, so retention "
                "acts conservatively — an unknown age is never treated as an "
                "expired record")
        elif age_days > _retention_days(policy, event):
            action, reason = DELETE_CANDIDATE, (
                f"recorded {age_days} days ago, beyond the "
                f"{_retention_days(policy, event)}-day "
                f"{retention_class(event).lower()} retention window")
        elif age_days > int(policy["archive_after_days"]):
            action, reason = ARCHIVE, (
                f"recorded {age_days} days ago, beyond the "
                f"{int(policy['archive_after_days'])}-day archive threshold "
                f"and inside its retention window")
        else:
            action, reason = RETAIN, f"recorded {age_days} days ago, inside its retention window"
        counts[action] += 1
        rows.append({
            "event_id": event.get("event_id"),
            "retention_class": retention_class(event),
            "observed_at": observed or None,
            "age_days": age_days,
            "action": action,
            "reason": reason,
        })
    return {
        "schema": "cryptoscan.cryptolog-retention-plan/1",
        "generated_at": now.isoformat(),
        "policy": dict(policy),
        "counts": counts,
        "rows": rows,
        "proven": [
            "each action is derived from the recorded observation time and "
            "the stated policy, deterministically",
        ],
        "not_proven": [
            "that any deletion is approved: DELETE_CANDIDATE is a projection, "
            "and execution needs a named disposition this plan does not grant",
            "that execution occurred: a plan is never presented as a "
            "production change",
        ],
        "note": "a retention plan is a projection over recorded events; "
                "executing it is a separate, disposition-gated act",
    }
