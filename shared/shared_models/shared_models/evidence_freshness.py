"""Evidence freshness and confidence tracking (roadmap item 2).

An observation is true *when it was taken* — and a bank that reads a six-month-old
TLS capture as today's cipher suite is being misled by its own tooling. This module
answers two questions honestly:

* **how old is this evidence?** — ``freshness_of`` classifies age against a per-type
  decay policy (a runtime observation ages out fast, a vendor declaration slowly),
  and a record with no ``observed_at`` is ``UNKNOWN`` age — never "fresh";
* **what confidence does it still deserve?** — ``tracked_confidence`` takes the
  confidence minted when the evidence was recorded and *lowers* it as the record
  ages. It never raises confidence, and it never invents a timestamp to justify
  keeping one.

"I do not know when this was observed" is not "this is fine": an unknown-age record
reports ``UNKNOWN`` freshness and its confidence is capped, not carried.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

FRESHNESS_SCHEMA = "cryptoscan.evidence-freshness/1"

#: freshness states, strongest to weakest. ``UNKNOWN`` is not between them: it is the
#: honest answer when the age cannot be computed at all.
FRESH: str = "FRESH"
AGING: str = "AGING"
STALE: str = "STALE"
EXPIRED: str = "EXPIRED"
UNKNOWN: str = "UNKNOWN"
FRESHNESS_STATES: tuple[str, ...] = (FRESH, AGING, STALE, EXPIRED, UNKNOWN)

#: default decay policy in days, per evidence type. Runtime evidence describes a
#: moment in the system's life and decays fastest; a certificate observation holds
#: until the certificate moves; a vendor declaration is a document. A type with no
#: policy entry decays as ``DEFAULT`` and says so in its report.
POLICY_DAYS: dict[str, int] = {
    "RUNTIME_OBSERVED": 7,
    "NETWORK_ACTIVE_OBSERVED": 7,
    "NETWORK_PASSIVE_OBSERVED": 14,
    "STATIC_OBSERVED": 90,
    "CERTIFICATE_OBSERVED": 180,
    "AUDIT_OBSERVED": 180,
    "CONFIGURED": 30,
    "VENDOR_DECLARED": 365,
    "IMPORTED": 180,
    "INFERRED": 30,
}
DEFAULT_POLICY_DAYS: int = 90

#: confidence rank for capping: a downgraded record can never keep its old ceiling
_CONFIDENCE_RANK: dict[str, int] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
_RANK_CONFIDENCE: dict[int, str] = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNKNOWN"}


def _as_moment(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value.strip():
        try:
            moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def policy_for(evidence_type: str) -> tuple[int, str]:
    """``(max_age_days, policy_source)`` for an evidence type — the source is reported
    so a reader can see when a record aged out under the default policy instead of a
    type-specific one."""
    kind = str(evidence_type or "").upper()
    if kind in POLICY_DAYS:
        return POLICY_DAYS[kind], "type"
    return DEFAULT_POLICY_DAYS, "default"


def freshness_of(observed_at: Any, *, evidence_type: str = "UNKNOWN",
                 now: datetime | None = None) -> dict[str, Any]:
    """Classify one record's age. A missing or unparseable timestamp is ``UNKNOWN``.

    The states: ``FRESH`` (inside the policy's first third), ``AGING`` (inside the
    policy), ``STALE`` (past the policy — still readable, no longer current),
    ``EXPIRED`` (past twice the policy — should not support a new decision), and
    ``UNKNOWN`` (no clock to compare against — which is never reported as fresh).
    """
    max_days, source = policy_for(evidence_type)
    moment = _as_moment(observed_at)
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    if moment is None:
        return {
            "schema": FRESHNESS_SCHEMA, "state": UNKNOWN, "age_days": None,
            "max_age_days": max_days, "policy": source,
            "reason": ("no observed_at to age this record from; an unknown-age record "
                       "is not a fresh one"),
        }
    age_days = max(0.0, (reference - moment).total_seconds() / 86400.0)
    if age_days <= max_days / 3:
        state, reason = FRESH, "inside the first third of its policy window"
    elif age_days <= max_days:
        state, reason = AGING, "inside its policy window and no longer new"
    elif age_days <= 2 * max_days:
        state, reason = STALE, ("past its policy window: still readable evidence, "
                               "no longer a current statement")
    else:
        state, reason = EXPIRED, ("past twice its policy window: must not support a "
                                 "new decision without re-collection")
    return {
        "schema": FRESHNESS_SCHEMA, "state": state, "age_days": round(age_days, 3),
        "max_age_days": max_days, "policy": source, "reason": reason,
    }


def _cap_for(state: str) -> int:
    if state == FRESH:
        return 3  # no cap below the top
    if state == AGING:
        return 3
    if state == STALE:
        return 1  # stale evidence caps at LOW
    return 0  # EXPIRED and UNKNOWN cap at UNKNOWN


def tracked_confidence(record: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """The confidence this record still deserves: its minted confidence, only lower.

    Age never *raises* confidence and never leaves a stale record holding a ``HIGH``
    it earned when the world matched it. A record with no observed_at is capped at
    ``MEDIUM`` — the platform will not pretend to know the age, and will not spend
    the record's original certainty pretending either.
    """
    minted = str(record.get("confidence") or "UNKNOWN").upper()
    minted_rank = _CONFIDENCE_RANK.get(minted, 0)
    fresh = freshness_of(record.get("observed_at"),
                         evidence_type=str(record.get("evidence_type") or "UNKNOWN"),
                         now=now)
    if fresh["state"] == UNKNOWN:
        # no clock: cap at MEDIUM, never stronger, and say why
        cap = 2
    else:
        cap = _cap_for(fresh["state"])
    effective = min(minted_rank, cap)
    return {
        "schema": FRESHNESS_SCHEMA,
        "minted": minted,
        "state": fresh["state"],
        "effective": _RANK_CONFIDENCE[effective],
        "downgraded": _RANK_CONFIDENCE[effective] != minted,
        "freshness": fresh,
        "note": ("confidence tracks evidence age: it is lowered as a record ages and "
                 "never raised — an old observation is not a new certainty"),
    }
