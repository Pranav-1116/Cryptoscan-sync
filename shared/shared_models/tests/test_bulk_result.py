"""Bulk-result contract tests (gap analysis §B: bulk partial success)."""

from __future__ import annotations

import pytest

from shared_models.bulk_result import (
    BULK_SCHEMA, ACCEPTED, REJECTED, SKIPPED,
    bulk_result, item, reject_all,
)


def test_every_outcome_carries_a_reason():
    row = item("day-1", ACCEPTED, "written")
    assert row == {"key": "day-1", "outcome": ACCEPTED, "reason": "written"}
    with pytest.raises(ValueError):
        item("day-1", ACCEPTED, "")
    with pytest.raises(ValueError):
        item("day-1", ACCEPTED, "   ")


def test_unknown_outcome_is_refused():
    with pytest.raises(ValueError):
        item("day-1", "MAYBE", "invented outcome")


def test_totals_are_computed_from_items():
    result = bulk_result([
        item("a", ACCEPTED, "written"),
        item("b", REJECTED, "invalid ISO date"),
        item("c", SKIPPED, "value unchanged"),
    ])
    assert result["schema"] == BULK_SCHEMA
    assert result["totals"] == {"accepted": 1, "rejected": 1, "skipped": 1, "total": 3}
    assert result["partial"] is True
    assert result["complete"] is False
    assert result["has_rejections"] is True


def test_all_rejected_batch_never_claims_success():
    result = bulk_result([item("a", REJECTED, "invalid ISO date")])
    assert result["totals"]["accepted"] == 0
    assert result["partial"] is False
    assert result["complete"] is False
    assert result["has_rejections"] is True


def test_all_accepted_is_complete_not_partial():
    result = bulk_result([item("a", ACCEPTED, "written"), item("b", ACCEPTED, "written")])
    assert result["complete"] is True
    assert result["partial"] is False
    assert result["has_rejections"] is False


def test_skips_alone_are_not_a_success_claim():
    result = bulk_result([item("a", SKIPPED, "idempotent replay")])
    assert result["complete"] is False
    assert result["totals"] == {"accepted": 0, "rejected": 0, "skipped": 1, "total": 1}


def test_reasonless_items_are_refused_by_the_builder():
    with pytest.raises(ValueError):
        bulk_result([{"key": "a", "outcome": ACCEPTED, "reason": ""}])
    with pytest.raises(ValueError):
        bulk_result([{"key": "a", "outcome": "UNKNOWN", "reason": "x"}])


def test_reject_all_still_reports_each_key():
    result = reject_all(["a", "b"], "batch refused")
    assert result["totals"]["rejected"] == 2
    assert [row["key"] for row in result["items"]] == ["a", "b"]
    assert all(row["reason"] == "batch refused" for row in result["items"])
