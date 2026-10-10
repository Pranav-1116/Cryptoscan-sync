"""Verification / confidence / staleness engine tests (spec #23, #24, #25)."""

from __future__ import annotations

import pytest

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


# ---------------------------------------------------------------------------
# Evidence freshness decay (audit 49 P0#3, round 27)
# ---------------------------------------------------------------------------

def test_decay_factor_math():
    from privacy.state import decay_factor

    assert decay_factor(0, 86400.0) == 1.0
    assert decay_factor(-5, 86400.0) == 1.0            # clock skew -> no decay
    assert decay_factor(None, 86400.0) == 0.0          # never observed -> no freshness
    assert decay_factor(86400.0, 86400.0) == pytest.approx(0.5)
    assert decay_factor(2 * 86400.0, 86400.0) == pytest.approx(0.25)
    assert decay_factor(86400.0, 2 * 86400.0) == pytest.approx(0.5 ** 0.5)
    with pytest.raises(ValueError):
        decay_factor(10, 0)


def test_evidence_half_life_by_class():
    from privacy.state import (DEFAULT_EVIDENCE_HALF_LIFE, EVIDENCE_HALF_LIVES,
                               evidence_half_life)

    assert evidence_half_life("runtime") == EVIDENCE_HALF_LIVES["RUNTIME"]
    assert evidence_half_life("BINARY") > evidence_half_life("RUNTIME")
    # None (unknown provenance) is honestly UNRANKED, per the authority model
    assert evidence_half_life(None) == EVIDENCE_HALF_LIVES["UNRANKED"]
    assert evidence_half_life("no-such-class") == DEFAULT_EVIDENCE_HALF_LIFE


def test_decay_confidence_halves_score_per_half_life():
    from privacy.state import Confidence, decay_confidence

    base = Confidence(score=0.9, quality="strong", reliability=0.9, evidence_count=2)
    now = 1_000_000.0
    half = 30 * 86400.0

    fresh = decay_confidence(base, now, now=now, half_life_seconds=half)
    assert fresh.score == pytest.approx(0.9)          # age 0: unchanged

    one_half = decay_confidence(base, now - half, now=now, half_life_seconds=half)
    assert one_half.score == pytest.approx(0.45)
    assert "freshness decay" in one_half.notes

    two_half = decay_confidence(base, now - 2 * half, now=now, half_life_seconds=half)
    assert two_half.score == pytest.approx(0.225)


def test_decay_confidence_never_observed_is_zero():
    from privacy.state import Confidence, decay_confidence

    base = Confidence(score=0.9, quality="strong", reliability=0.9, evidence_count=2)
    gone = decay_confidence(base, None, now=100.0)
    assert gone.score == 0.0


def test_decay_confidence_verified_keeps_floor():
    from privacy.state import VERIFIED_DECAY_FLOOR, Confidence, decay_confidence

    verified = Confidence(score=0.95, quality="strong", reliability=0.9,
                          evidence_count=3, verified=True)
    ancient = decay_confidence(verified, 0.0, now=10 * 365 * 86400.0)
    assert ancient.score == pytest.approx(VERIFIED_DECAY_FLOOR)
    assert ancient.verified is True


def test_decay_confidence_uses_evidence_class_half_life():
    from privacy.state import Confidence, decay_confidence

    base = Confidence(score=0.8, quality="strong", reliability=0.9, evidence_count=1)
    now = 1_000_000.0
    age = 14 * 86400.0
    # 14 days: two runtime half-lives, but far inside the binary half-life
    runtime = decay_confidence(base, now - age, now=now, evidence_class="RUNTIME")
    binary = decay_confidence(base, now - age, now=now, evidence_class="BINARY")
    assert runtime.score == pytest.approx(0.2)
    assert binary.score > 0.7
