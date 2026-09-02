"""Deterministic business-criticality scorer.

The same universal scanner discovers the same assets in every sector; the
*criticality* of an asset is what changes by sector. This module turns a
SectorProfile plus a few objective signals into a criticality tier — pure
function, no AI. The tier feeds risk weighting, PQC migration urgency and
report ordering.

Signals (all optional, all booleans/counts so they come straight from
discovery, never from human guesswork):

    customer_facing   serves end users / transactions
    internet_exposed  reachable from the public internet
    handles_pii       processes personal / regulated data
    production        is a production (vs dev/test) environment
    payment_path      sits on a payment / money-movement path
    safety_critical   failure causes physical-safety impact (OT/medical)
    crypto_strength   weak/legacy crypto present (True bumps criticality)
    downstream_count  number of systems that depend on it (blast radius)

The sector's ``asset_criticality`` map supplies the base tier from the asset
type keyword; signals can only raise (never lower) it, so a sector never
*under*-rates a crown jewel that discovery flags as sensitive.
"""

from __future__ import annotations

from typing import Any

from sector_profiles.catalog import TIER_RANK, SectorProfile

#: base tier for asset types a sector profile doesn't explicitly mention
_DEFAULT_BASE = "MEDIUM"

#: how many extra tier steps each signal contributes (most cap at top)
_SIGNAL_STEPS: dict[str, int] = {
    "safety_critical": 3,
    "payment_path": 2,
    "handles_pii": 1,
    "customer_facing": 1,
    "internet_exposed": 1,
    "crypto_strength": 1,  # weak/legacy crypto raises remediation urgency
}


def _base_tier(profile: SectorProfile, asset_type: str) -> str:
    """Highest tier whose keyword appears in the asset type string."""
    haystack = (asset_type or "").lower().replace("-", "_")
    best = _DEFAULT_BASE
    best_rank = TIER_RANK[best]
    for keyword, tier in profile.asset_criticality.items():
        if keyword in haystack and TIER_RANK.get(tier, 0) > best_rank:
            best, best_rank = tier, TIER_RANK.get(tier, 0)
    return best


def _signal_steps(signals: dict[str, Any]) -> int:
    steps = 0
    for name, weight in _SIGNAL_STEPS.items():
        if bool(signals.get(name)):
            steps += weight
    # production vs non-production
    env = str(signals.get("environment") or signals.get("env") or "production").lower()
    if env in {"dev", "development", "test", "staging", "sandbox"}:
        steps -= 2  # non-prod is materially less critical
    # blast radius from dependency count
    downstream = int(signals.get("downstream_count", 0) or 0)
    if downstream >= 20:
        steps += 2
    elif downstream >= 5:
        steps += 1
    return steps


def _clamp_tier(rank: int) -> str:
    rank = max(0, min(rank, len(TIER_RANK) - 1))
    for name, value in TIER_RANK.items():
        if value == rank:
            return name
    return "MEDIUM"


def score_criticality(profile: SectorProfile, asset_type: str, **signals: Any) -> str:
    """Return the criticality tier for an asset within a sector.

    Pure/deterministic: identical (profile, asset_type, signals) always
    yields the same tier.
    """
    base = _base_tier(profile, asset_type)
    rank = TIER_RANK[base] + _signal_steps(signals)
    return _clamp_tier(rank)


def risk_weight(tier: str) -> float:
    """Multiplier used by downstream risk/quantum scoring.

    Matches the convention in quantum.risk (CRITICAL ~1.5, HIGH ~1.2).
    """
    weights = {
        "VERY_LOW": 0.7,
        "LOW": 0.85,
        "MEDIUM": 1.0,
        "HIGH": 1.2,
        "VERY_HIGH": 1.35,
        "MISSION_CRITICAL": 1.5,
    }
    return weights.get(tier, 1.0)
