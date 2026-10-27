"""Change classification taxonomy for the live-crypto journal (audit 68 P0#3, round 29).

The §34 timeline records event *types*; report 68 asked for a full change
taxonomy — what class of change each event is, how it bears on crypto
risk, and which direction it points. This module supplies that taxonomy
as pure functions over event dicts (the journal row's ``event_dict()``
shape or the in-process ``CryptoEvent.to_dict()`` shape — both carry
``event_type`` and an optional ``payload``).

Two layers, both deterministic:

* **event-level classification** — every one of the 15 event types maps
  to exactly one change class with a crypto-impact weight and an honest
  direction (``UNKNOWN`` when the type alone cannot say);
* **payload-aware direction** — when the payload carries the old and
  new algorithm / key size, the direction is computed by comparison
  (a shrinking key size is DETERIORATION, a growing one IMPROVEMENT),
  using the shared designation ranks — never guessed from the label.

Impact weights are ordinals for sorting and rollups, not risk scores:
``ALGORITHM_REMOVED`` matters more than ``CONFIG_CHANGED``; the risk
engine stays the single source of risk truth.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

# --------------------------------------------------------------------- #
# the taxonomy
# --------------------------------------------------------------------- #

#: change classes
DISCOVERY = "DISCOVERY"        # something was detected (no prior state)
ADDITION = "ADDITION"          # new crypto material appeared
REMOVAL = "REMOVAL"            # crypto material disappeared
MODIFICATION = "MODIFICATION"  # existing crypto changed shape
OPERATIONAL = "OPERATIONAL"    # lifecycle housekeeping (expiry, renewal)
ALERT = "ALERT"                # unexplained / unknown operation

#: crypto-impact ordinals (sorting/rollup weights, NOT risk scores)
IMPACT_NONE = 0
IMPACT_LOW = 1
IMPACT_MEDIUM = 2
IMPACT_HIGH = 3

#: directions
IMPROVEMENT = "IMPROVEMENT"
DETERIORATION = "DETERIORATION"
NEUTRAL = "NEUTRAL"
UNKNOWN = "UNKNOWN"

#: designation rank for algorithm-quality comparison (shared vocabulary
#: with the exposure surface; higher = weaker)
_DESIGNATION_RANK = {
    "DISALLOWED": 4,
    "DEPRECATED": 3,
    "RESTRICTED": 3,
    "ALLOWED": 1,
}

TAXONOMY: dict[str, dict[str, Any]] = {
    "ALGORITHM_DETECTED": {
        "change_class": DISCOVERY, "impact": IMPACT_LOW, "direction": NEUTRAL,
        "description": "crypto use detected where none was recorded before",
    },
    "ALGORITHM_REMOVED": {
        "change_class": REMOVAL, "impact": IMPACT_HIGH, "direction": UNKNOWN,
        "description": "crypto use no longer observed; direction depends on "
                       "what was removed (payload-aware when available)",
    },
    "CERT_NEW": {
        "change_class": ADDITION, "impact": IMPACT_LOW, "direction": NEUTRAL,
        "description": "certificate added to the observed surface",
    },
    "CERT_RENEWED": {
        "change_class": OPERATIONAL, "impact": IMPACT_LOW, "direction": IMPROVEMENT,
        "description": "certificate renewed (validity extended)",
    },
    "CERT_EXPIRING": {
        "change_class": OPERATIONAL, "impact": IMPACT_MEDIUM, "direction": DETERIORATION,
        "description": "certificate approaching expiry",
    },
    "CERT_REVOKED": {
        "change_class": REMOVAL, "impact": IMPACT_HIGH, "direction": DETERIORATION,
        "description": "certificate revoked — trust withdrawn",
    },
    "KEY_ROTATED": {
        "change_class": MODIFICATION, "impact": IMPACT_MEDIUM, "direction": IMPROVEMENT,
        "description": "key material rotated",
    },
    "KEY_EXPIRED": {
        "change_class": OPERATIONAL, "impact": IMPACT_MEDIUM, "direction": DETERIORATION,
        "description": "key past its validity",
    },
    "LIBRARY_UPGRADED": {
        "change_class": MODIFICATION, "impact": IMPACT_MEDIUM, "direction": UNKNOWN,
        "description": "crypto library version changed; direction depends on "
                       "the versions (payload-aware when available)",
    },
    "TLS_POLICY_CHANGED": {
        "change_class": MODIFICATION, "impact": IMPACT_HIGH, "direction": UNKNOWN,
        "description": "negotiated TLS policy changed",
    },
    "PQC_CAPABILITY_CHANGED": {
        "change_class": MODIFICATION, "impact": IMPACT_HIGH, "direction": UNKNOWN,
        "description": "post-quantum capability appeared or disappeared",
    },
    "PROTOCOL_CHANGED": {
        "change_class": MODIFICATION, "impact": IMPACT_HIGH, "direction": UNKNOWN,
        "description": "protocol version/selection changed",
    },
    "CONFIG_CHANGED": {
        "change_class": MODIFICATION, "impact": IMPACT_LOW, "direction": UNKNOWN,
        "description": "crypto-relevant configuration changed",
    },
    "IMPLEMENTATION_CHANGED": {
        "change_class": MODIFICATION, "impact": IMPACT_MEDIUM, "direction": UNKNOWN,
        "description": "the implementing library/module behind a use changed",
    },
    "UNKNOWN_CRYPTO_OPERATION": {
        "change_class": ALERT, "impact": IMPACT_HIGH, "direction": UNKNOWN,
        "description": "crypto operation that could not be classified — "
                       "surfaced, never guessed",
    },
}

UNKNOWN_CLASSIFICATION = {
    "change_class": ALERT,
    "impact": IMPACT_MEDIUM,
    "direction": UNKNOWN,
    "description": "unrecognized event type — classified as ALERT, never guessed",
}


def classify_change(event: Mapping[str, Any]) -> dict[str, Any]:
    """Classify one journal event; payload-aware when the payload says."""
    event_type = str(event.get("event_type") or "").upper()
    entry = dict(TAXONOMY.get(event_type, UNKNOWN_CLASSIFICATION))
    payload = event.get("payload") if isinstance(event.get("payload"), Mapping) else {}

    # payload-aware direction: old/new key size
    old_size, new_size = payload.get("old_key_size"), payload.get("new_key_size")
    if isinstance(old_size, int) and isinstance(new_size, int):
        entry["direction"] = (DETERIORATION if new_size < old_size
                              else IMPROVEMENT if new_size > old_size else NEUTRAL)

    # payload-aware direction: old/new algorithm designation
    old_alg = str(payload.get("old_algorithm") or "").upper()
    new_alg = str(payload.get("new_algorithm") or "").upper()
    if old_alg and new_alg:
        try:
            from shared_models.algorithm_registry import parse_algorithm
            old_rank = _DESIGNATION_RANK.get(
                str(parse_algorithm(old_alg).status).upper(), None)
            new_rank = _DESIGNATION_RANK.get(
                str(parse_algorithm(new_alg).status).upper(), None)
        except Exception:  # noqa: BLE001 — registry unavailable: stay UNKNOWN
            old_rank = new_rank = None
        if old_rank is not None and new_rank is not None:
            entry["direction"] = (IMPROVEMENT if new_rank < old_rank
                                  else DETERIORATION if new_rank > old_rank
                                  else NEUTRAL)

    return entry


def classify_timeline(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Classify a timeline of events and roll it up per change class."""
    classified: list[dict[str, Any]] = []
    by_class: dict[str, int] = {}
    by_direction: dict[str, int] = {}
    unknown_types: set[str] = set()
    for event in events or []:
        event_type = str(event.get("event_type") or "").upper()
        entry = classify_change(event)
        if event_type not in TAXONOMY and event_type:
            unknown_types.add(event_type)
        by_class[entry["change_class"]] = by_class.get(entry["change_class"], 0) + 1
        by_direction[entry["direction"]] = by_direction.get(entry["direction"], 0) + 1
        classified.append({**dict(event), "classification": entry})

    return {
        "events": classified,
        "event_count": len(classified),
        "by_change_class": by_class,
        "by_direction": by_direction,
        "unrecognized_event_types": sorted(unknown_types),
        "impact_note": "impact ordinals are sorting/rollup weights, not risk "
                       "scores — the risk engine stays the single source of "
                       "risk truth",
    }
