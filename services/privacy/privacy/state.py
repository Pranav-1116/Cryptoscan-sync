"""Verification, confidence and staleness state (spec #23, #24, #25).

The 95%+ cryptographic-detection target must be treated as a measurable KPI, not
a marketing claim. This module gives every observation a **verification state**
and a **confidence tuple** and decides when an asset has gone **stale**, so the
platform never silently reports a long-gone asset as green.

The supported verification states:

    VERIFIED      -> independently confirmed by a strong secondary source
    PROBABLE      -> high-confidence but not independently confirmed
    UNVERIFIED    -> a single weak source, no corroboration
    CONFLICTING   -> sources disagree
    UNKNOWN       -> anything that could not be classified
    STALE         -> an asset that used to be known but has not been observed
                     within its freshness window

All functions are pure/deterministic and testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

#: ordered confidence tiers (high -> low) — used to word the UI honestly.
CONFIDENCE_TIERS = ("high", "medium", "low", "unknown")

#: verification states in order of trustworthiness.
VERIFICATION_STATES = ("VERIFIED", "PROBABLE", "UNVERIFIED",
                       "CONFLICTING", "UNKNOWN", "STALE")

#: observation freshness windows (seconds) used by :func:`staleness`.
DEFAULT_FRESHNESS: dict[str, int] = {
    "live": 120,          # 2 minutes
    "stale": 3 * 86400,   # 3 days
    "unknown": 30 * 86400,  # 30 days
}

#: relative reliability of a source kind (0..1). Vendors / agents that observe
#: the live runtime are strong; a pure network presence probe is weaker.
SOURCE_RELIABILITY: dict[str, float] = {
    "agent": 0.99,
    "runtime": 0.98,
    "crypto": 0.95,
    "vendor": 0.85,
    "cloud": 0.9,
    "hardware": 0.8,
    "certificate": 0.8,
    "network": 0.6,
    "application": 0.7,
}


@dataclass(frozen=True)
class Confidence:
    """A measured confidence, not a number on a sticker."""

    score: float          # 0..1
    quality: str          # strong | medium | weak
    reliability: float    # 0..1 source reliability
    evidence_count: int
    verified: bool = False
    notes: str = ""

    @property
    def tier(self) -> str:
        if self.score >= 0.9:
            return "high"
        if self.score >= 0.7:
            return "medium"
        if self.score >= 0.5:
            return "low"
        return "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "quality": self.quality,
            "reliability": round(self.reliability, 3),
            "evidence_count": self.evidence_count,
            "verified": self.verified,
            "tier": self.tier,
            "notes": self.notes,
        }


def confidence_0() -> Confidence:
    return Confidence(score=0.0, quality="weak", reliability=0.0, evidence_count=0)


def _quality(reliability: float) -> str:
    if reliability >= 0.9:
        return "strong"
    if reliability >= 0.7:
        return "medium"
    return "weak"


def confidence_from_sources(sources: Mapping[str, str], *, verified: bool = False,
                            evidence_weight: float = 1.0) -> Confidence:
    """Combine a set of source kinds (``source_kind -> state``) into one score.

    Each distinct corroborating source raises confidence; a contradictory source
    ``conflicting`` lowers it. Explicit verification adds a strong floor.
    """
    if not sources:
        return confidence_0()
    rels = [SOURCE_RELIABILITY.get(k, 0.5) for k in sources if k]
    reliab = sum(rels) / len(rels) if rels else 0.5
    cred = max(rels) if rels else 0.5
    conflicting = any(str(v).lower() in ("conflicting", "conflict") for v in sources.values())
    score = 0.3 + 0.6 * cred
    score *= (1 + 0.15 * (len(sources) - 1))   # corroboration bonus
    if conflicting:
        score -= 0.4
    if verified:
        score = max(score, 0.95)
    score = max(0.0, min(1.0, score))
    return Confidence(score=score, quality=_quality(reliab),
                      reliability=reliab, evidence_count=len(sources),
                      verified=verified)


def coerce_verification_state(state: str) -> str:
    """Coerce a free-form state string into one of the sanctioned states."""
    s = (state or "").strip().upper()
    if s in VERIFICATION_STATES:
        return s
    # synonyms
    synonyms = {
        "GOOD": "VERIFIED", "CONFIRMED": "VERIFIED", "CONFIRM": "VERIFIED",
        "CLEAN": "VERIFIED", "OK": "VERIFIED",
        "LIKELY": "PROBABLE", "MAYBE": "PROBABLE", "SUSPECTED": "PROBABLE",
        "PROBABLY": "PROBABLE",
        "TENTATIVE": "UNVERIFIED", "SINGLE": "UNVERIFIED", "UNCONFIRMED": "UNVERIFIED",
        "DISAGREE": "CONFLICTING", "MISMATCH": "CONFLICTING", "DISAGREEMENT": "CONFLICTING",
        "GONE": "STALE", "NOT_SEEN": "STALE", "ABSENT": "STALE",
    }
    return synonyms.get(s, "UNKNOWN")


def verification_state(confidence: Confidence, *, conflicted: bool = False,
                       corroborated: bool = False) -> str:
    """Derive the verification state from a confidence tuple + signals."""
    if conflicted:
        return "CONFLICTING"
    if confidence.verified or (corroborated and confidence.tier == "high"):
        return "VERIFIED"
    if confidence.tier == "high":
        return "PROBABLE"
    if confidence.tier == "medium":
        return "UNVERIFIED"
    return "UNKNOWN"


def staleness(last_seen_epoch: float | None, *, now: float,
              windows: Mapping[str, int] | None = None) -> dict[str, Any]:
    """Classify how fresh an asset is.

    * ``live``     -- observed within ``windows['live']`` (default 120s)
    * ``stale``    -- observed within ``windows['stale']`` (default 3 days)
    * ``unknown``  -- older than the stale window, or never observed
    * ``never``    -- ``last_seen`` is None

    Returns a dict with ``state`` and ``age_seconds``.
    """
    w = dict(DEFAULT_FRESHNESS)
    if windows:
        w.update({k: int(v) for k, v in windows.items()})
    if last_seen_epoch is None:
        return {"state": "never", "age_seconds": None}
    age = max(0.0, now - last_seen_epoch)
    if age <= w["live"]:
        state = "live"
    elif age <= w["stale"]:
        state = "stale"
    else:
        state = "unknown"
    return {"state": state, "age_seconds": round(age, 1)}


def health_for_asset(observed_state: dict[str, Any], *, now: float) -> dict[str, Any]:
    """Merge an asset's verification/staleness signals into a status one can
    safely show (never green for something unobserved)."""
    last_seen = observed_state.get("last_seen_epoch")
    stal = staleness(last_seen, now=now)
    ver_state = coerce_verification_state(str(observed_state.get("verification", "")))
    # an asset that has not been seen cannot truthfully display healthy/green
    if stal["state"] in ("unknown", "never"):
        ver_state = "STALE" if stal["state"] == "unknown" else "UNKNOWN"
    return {
        "verification": ver_state,
        "freshness": stal["state"],
        "age_seconds": stal["age_seconds"],
        "display_status": "healthy" if ver_state == "VERIFIED" else (
            "probable" if ver_state == "PROBABLE" else (
                "unverified" if ver_state == "UNVERIFIED" else
                "conflicting" if ver_state == "CONFLICTING" else
                "stale" if ver_state == "STALE" else "unknown")),
    }
