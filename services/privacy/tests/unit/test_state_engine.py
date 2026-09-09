"""Verification / confidence / staleness engine tests (spec #23, #24, #25)."""

from __future__ import annotations

from privacy.state import (
    Confidence,
    confidence_from_sources,
    coerce_verification_state,
    health_for_asset,
    staleness,
    verification_state,
)


def test_confidence_corroboration_raises_score():
    single = confidence_from_sources({"crypto": "observed"})
    multi = confidence_from_sources({"crypto": "observed", "network": "observed",
                                     "agent": "observed"})
    assert multi.score > single.score


def test_confidence_conflicting_lowers_score():
    c = confidence_from_sources({"network": "conflicting", "crypto": "observed"})
    assert c.score < confidence_from_sources({"crypto": "observed"}).score


def test_verified_floor():
    c = confidence_from_sources({"network": "observed"}, verified=True)
    assert c.score >= 0.95
    assert c.tier == "high"


def test_verification_states_derivation():
    high = Confidence(0.95, "strong", 0.9, 2)
    verified = Confidence(0.95, "strong", 0.9, 2, verified=True)
    assert verification_state(verified) == "VERIFIED"
    assert verification_state(high) == "PROBABLE"
    med = Confidence(0.7, "medium", 0.7, 2)
    assert verification_state(med) == "UNVERIFIED"
    low = Confidence(0.2, "weak", 0.2, 1)
    assert verification_state(low) == "UNKNOWN"
    assert verification_state(high, conflicted=True) == "CONFLICTING"


def test_coerce_verification_state_synonyms():
    assert coerce_verification_state("confirm") == "VERIFIED"
    assert coerce_verification_state("likely") == "PROBABLE"
    assert coerce_verification_state("?" ) == "UNKNOWN"
    assert coerce_verification_state("stale") == "STALE"


def test_staleness_windows():
    now = 1_000_000.0
    assert staleness(now - 60, now=now)["state"] == "live"
    assert staleness(now - 3600, now=now)["state"] == "stale"
    assert staleness(now - 40 * 86400, now=now)["state"] == "unknown"
    assert staleness(None, now=now)["state"] == "never"


def test_health_for_asset_never_green_when_stale():
    now = 1_000_000.0
    # an asset last seen 40 days ago, even labelled "verified", must NOT be green
    h = health_for_asset({"verification": "VERIFIED", "last_seen_epoch": now - 40 * 86400},
                         now=now)
    assert h["display_status"] in ("stale", "unknown")
    assert h["verification"] == "STALE"


def test_health_for_asset_fresh_verified_is_healthy():
    now = 1_000_000.0
    h = health_for_asset({"verification": "VERIFIED", "last_seen_epoch": now - 30}, now=now)
    assert h["display_status"] == "healthy"
