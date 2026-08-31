"""Policy tests — TIMELINE condition (previously untested)."""

from __future__ import annotations

from datetime import date

import pytest

from policy.conditions.timeline_condition import TimelineCondition, _parse_day


@pytest.fixture
def timeline() -> TimelineCondition:
    return TimelineCondition()


class TestTimelineCondition:
    def test_retired_algorithm_after_deadline_fails(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "SHA1", "purpose": "SIGNING"},
            {
                "retired_algorithms": ["SHA1", "MD5"],
                "after": "2024-01-01",
                "after_result": "FAIL",
            },
        )
        assert outcome.result == "FAIL"
        assert "SHA1" in outcome.message

    def test_retired_algorithm_after_deadline_warn(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "MD5", "evaluation_date": date(2026, 6, 1)},
            {"retired_algorithms": ["MD5"], "after": "2025-01-01",
             "after_result": "WARN"},
        )
        assert outcome.result == "WARN"

    def test_warn_window_before_deadline(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "DES", "evaluation_date": date(2026, 1, 1)},
            {
                "retired_algorithms": ["DES"],
                "after": "2026-12-31",
                "warn_after": "2026-01-01",
            },
        )
        assert outcome.result == "WARN"
        assert "replace" in outcome.message

    def test_before_warn_window_passes(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "DES", "evaluation_date": date(2025, 1, 1)},
            {"retired_algorithms": ["DES"], "after": "2026-12-31",
             "warn_after": "2026-01-01"},
        )
        assert outcome.result == "PASS"
        assert "not yet in force" in outcome.message

    def test_approved_algorithm_is_exception_to_retirement(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "SHA1", "evaluation_date": date(2026, 6, 1)},
            {"retired_algorithms": ["SHA1", "MD5"],
             "approved_algorithms": ["SHA1"]},
        )
        assert outcome.result == "PASS"

    def test_approved_algorithm_listed_but_algorithm_different(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "MD5", "evaluation_date": date(2026, 6, 1)},
            {"retired_algorithms": ["SHA1", "MD5"],
             "approved_algorithms": ["SHA1"],
             "after": "2024-01-01"},
        )
        assert outcome.result == "FAIL"

    def test_not_on_retirement_list_not_applicable(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "AES"},
            {"retired_algorithms": ["SHA1", "MD5"]},
        )
        assert outcome.result == "NOT_APPLICABLE"

    def test_purpose_filter_not_applicable(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "SHA1", "purpose": "KEY_EXCHANGE"},
            {"retired_algorithms": ["SHA1"], "if_purpose": ["SIGNING"]},
        )
        assert outcome.result == "NOT_APPLICABLE"

    def test_purpose_filter_applies(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "SHA1", "purpose": "SIGNING",
             "evaluation_date": date(2026, 6, 1)},
            {"retired_algorithms": ["SHA1"], "if_purpose": ["SIGNING"],
             "after": "2024-01-01"},
        )
        assert outcome.result == "FAIL"

    def test_missing_scopes_not_applicable(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "SHA1", "scope": "public"},
            {"retired_algorithms": ["SHA1"], "required_scopes": ["private"]},
        )
        assert outcome.result == "NOT_APPLICABLE"
        assert "scope" in outcome.message.lower()

    def test_invalid_after_result_defaults_to_fail(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "SHA1", "evaluation_date": date(2026, 6, 1)},
            {"retired_algorithms": ["SHA1"], "after": "2024-01-01",
             "after_result": "BOGUS"},
        )
        assert outcome.result == "FAIL"

    def test_custom_message_used(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "SHA1", "evaluation_date": date(2026, 6, 1)},
            {"retired_algorithms": ["SHA1"], "after": "2024-01-01",
             "message": "SHA1 signing is prohibited"},
        )
        assert outcome.message == "SHA1 signing is prohibited"

    def test_retire_after_alias(self, timeline):
        outcome = timeline.evaluate(
            {"algorithm": "RC4", "evaluation_date": date(2026, 6, 1)},
            {"retired_algorithms": ["RC4"], "retire_after": "2025-06-01"},
        )
        assert outcome.result == "FAIL"

    def test_condition_type(self, timeline):
        assert timeline.CONDITION_TYPE == "TIMELINE"


class TestParseDay:
    def test_none(self):
        assert _parse_day(None) is None

    def test_date_object(self):
        assert _parse_day(date(2026, 1, 2)) == date(2026, 1, 2)

    def test_iso_string(self):
        assert _parse_day("2026-03-04") == date(2026, 3, 4)

    def test_datetime_truncated_to_date(self):
        from datetime import datetime

        assert _parse_day(datetime(2026, 5, 6, 12, 30)) == date(2026, 5, 6)

    def test_garbage_returns_none(self):
        assert _parse_day("not-a-date") is None
