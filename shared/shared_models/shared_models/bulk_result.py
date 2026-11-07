"""Bulk-operation result contract (gap analysis §B).

Bulk operations return partial success per item: accepted, rejected or
skipped, with an individual reason for every outcome. A bulk call must never
turn a mix of outcomes into one opaque success, and totals are computed
from the items — never supplied by the caller and never invented.
"""

from __future__ import annotations

from typing import Iterable, Sequence

BULK_SCHEMA = "cryptoscan.bulk-result/1"

ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"
SKIPPED = "SKIPPED"
OUTCOMES = frozenset({ACCEPTED, REJECTED, SKIPPED})


def item(key: str, outcome: str, reason: str) -> dict:
    """One per-item outcome. Every item carries a reason, including accepts."""
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {sorted(OUTCOMES)}; got {outcome!r}")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("every bulk item needs a non-empty reason, including accepts")
    if not isinstance(key, str) or not key.strip():
        raise ValueError("every bulk item needs a non-empty key")
    return {"key": key, "outcome": outcome, "reason": reason.strip()}


def bulk_result(items: Sequence[dict]) -> dict:
    """Aggregate per-item outcomes into the partial-success envelope.

    - totals are derived from the items (a claimed total never overrides)
    - ``partial`` is true only for a genuine mix: some accepted, some not
    - ``complete`` is true only when every item was accepted
    - an all-rejected batch is honest: totals say so, nothing claims success
    """
    rows = list(items)
    for row in rows:
        if row.get("outcome") not in OUTCOMES:
            raise ValueError(f"item {row!r} carries no valid outcome")
        if not (row.get("reason") or "").strip():
            raise ValueError(f"item {row!r} carries no reason")
    accepted = sum(1 for row in rows if row["outcome"] == ACCEPTED)
    rejected = sum(1 for row in rows if row["outcome"] == REJECTED)
    skipped = sum(1 for row in rows if row["outcome"] == SKIPPED)
    if accepted + rejected + skipped != len(rows):
        raise ValueError("item outcomes do not cover the batch")
    return {
        "schema": BULK_SCHEMA,
        "items": rows,
        "totals": {"accepted": accepted, "rejected": rejected,
                   "skipped": skipped, "total": len(rows)},
        "partial": 0 < accepted < len(rows),
        "complete": accepted == len(rows) and len(rows) > 0,
        "has_rejections": rejected > 0,
    }


def reject_all(keys: Iterable[str], reason: str) -> dict:
    """A batch refused as a whole still reports per-item outcomes."""
    return bulk_result([item(str(key), REJECTED, reason) for key in keys])
