"""Evidence freshness and confidence tracking — roadmap item 2 acceptance rows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shared_models.evidence_freshness import (
    AGING,
    EXPIRED,
    FRESH,
    STALE,
    UNKNOWN,
    freshness_of,
    policy_for,
    tracked_confidence,
)

NOW = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)


def at(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


class TestFreshnessClassification:

    def test_a_new_observation_is_fresh(self):
        result = freshness_of(at(0.5), evidence_type="RUNTIME_OBSERVED", now=NOW)
        assert result["state"] == FRESH
        assert result["age_days"] == pytest.approx(0.5)

    def test_an_observation_inside_the_window_is_aging_not_fresh(self):
        result = freshness_of(at(5), evidence_type="RUNTIME_OBSERVED", now=NOW)
        assert result["state"] == AGING

    def test_past_the_policy_is_stale_but_still_readable(self):
        result = freshness_of(at(10), evidence_type="RUNTIME_OBSERVED", now=NOW)
        assert result["state"] == STALE
        assert "no longer a current statement" in result["reason"]

    def test_past_twice_the_policy_is_expired_and_must_not_support_new_decisions(self):
        result = freshness_of(at(20), evidence_type="RUNTIME_OBSERVED", now=NOW)
        assert result["state"] == EXPIRED
        assert "re-collection" in result["reason"]

    def test_a_missing_timestamp_is_unknown_never_fresh(self):
        for value in (None, "", "not-a-date", 12345):
            result = freshness_of(value, evidence_type="RUNTIME_OBSERVED", now=NOW)
            assert result["state"] == UNKNOWN
            assert result["age_days"] is None
            assert "not a fresh one" in result["reason"]

    def test_runtime_evidence_decays_faster_than_a_vendor_declaration(self):
        runtime_days, _ = policy_for("RUNTIME_OBSERVED")
        vendor_days, _ = policy_for("VENDOR_DECLARED")
        assert runtime_days < vendor_days
        # the same age is fresh for a declaration and stale for a runtime read
        age = at(10)
        assert freshness_of(age, evidence_type="RUNTIME_OBSERVED", now=NOW)["state"] == STALE
        assert freshness_of(age, evidence_type="VENDOR_DECLARED", now=NOW)["state"] == FRESH

    def test_an_unpolicyed_type_uses_the_default_and_says_so(self):
        result = freshness_of(at(1), evidence_type="SOMETHING_NEW", now=NOW)
        assert result["policy"] == "default"
        assert result["max_age_days"] == 90


class TestTrackedConfidence:

    def test_fresh_high_evidence_keeps_its_confidence(self):
        record = {"confidence": "HIGH", "observed_at": at(0.5),
                  "evidence_type": "RUNTIME_OBSERVED"}
        tracked = tracked_confidence(record, now=NOW)
        assert tracked["effective"] == "HIGH"
        assert tracked["downgraded"] is False

    def test_stale_evidence_is_downgraded_never_kept_at_high(self):
        record = {"confidence": "HIGH", "observed_at": at(10),
                  "evidence_type": "RUNTIME_OBSERVED"}
        tracked = tracked_confidence(record, now=NOW)
        assert tracked["effective"] == "LOW"
        assert tracked["downgraded"] is True

    def test_expired_evidence_has_no_effective_confidence_left(self):
        record = {"confidence": "HIGH", "observed_at": at(30),
                  "evidence_type": "RUNTIME_OBSERVED"}
        tracked = tracked_confidence(record, now=NOW)
        assert tracked["effective"] == "UNKNOWN"

    def test_age_never_raises_confidence(self):
        record = {"confidence": "LOW", "observed_at": at(0.1),
                  "evidence_type": "RUNTIME_OBSERVED"}
        tracked = tracked_confidence(record, now=NOW)
        assert tracked["effective"] == "LOW"  # fresh, but minted LOW stays LOW

    def test_a_record_with_no_clock_is_capped_not_trusted(self):
        record = {"confidence": "HIGH", "observed_at": None,
                  "evidence_type": "VENDOR_DECLARED"}
        tracked = tracked_confidence(record, now=NOW)
        assert tracked["freshness"]["state"] == UNKNOWN
        assert tracked["effective"] == "MEDIUM"  # capped: we do not know the age
        assert tracked["downgraded"] is True

    def test_the_report_explains_what_it_did(self):
        record = {"confidence": "HIGH", "observed_at": at(10),
                  "evidence_type": "RUNTIME_OBSERVED"}
        tracked = tracked_confidence(record, now=NOW)
        assert "never raised" in tracked["note"]
        assert tracked["freshness"]["policy"] == "type"
