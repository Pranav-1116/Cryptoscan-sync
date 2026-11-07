"""Retention planning tests (docs/cryptolog/01_PRODUCT_SPEC.md §10).

The plan is a projection: deterministic, conservative on unknown ages,
and DELETE_CANDIDATE is its strongest claim — never an executed deletion.
"""

from __future__ import annotations

from datetime import datetime, timezone

from shared_models.cryptolog_retention import (
    ARCHIVE, DELETE_CANDIDATE, RETAIN, plan, retention_class,
)

NOW = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)


def _event(event_id: str, kind: str, observed: str):
    return {
        "event_id": event_id,
        "logging_kind": kind,
        "observation": {"observed_at": observed},
    }


def test_retention_classes_follow_the_logging_kind():
    assert retention_class(_event("e1", "ACTIVITY", "")) == "SHORT"
    assert retention_class(_event("e2", "CHANGE", "")) == "LONG"
    assert retention_class(_event("e3", "AUDIT", "")) == "PERMANENT"


def test_the_plan_is_deterministic_and_projected():
    events = [
        _event("e_new", "ACTIVITY", "2026-11-01T00:00:00Z"),    # 6 days
        _event("e_mid", "ACTIVITY", "2026-08-01T00:00:00Z"),    # 98 days
        _event("e_old", "ACTIVITY", "2024-01-01T00:00:00Z"),    # ~1041 days
        _event("e_chg", "CHANGE", "2020-01-01T00:00:00Z"),      # beyond 3650? ~2503 -> ARCHIVE
    ]
    result = plan(events, {}, NOW)
    again = plan(events, {}, NOW)
    assert result == again, "the same inputs always produce the same plan"
    by_id = {r["event_id"]: r["action"] for r in result["rows"]}
    assert by_id == {
        "e_new": RETAIN,
        "e_mid": ARCHIVE,
        "e_old": DELETE_CANDIDATE,
        "e_chg": ARCHIVE,
    }
    assert result["counts"] == {RETAIN: 1, ARCHIVE: 2, DELETE_CANDIDATE: 1}
    assert "never presented as a production change" in result["not_proven"][1]


def test_an_unknown_age_is_never_treated_as_expired():
    result = plan([_event("e1", "ACTIVITY", "")], {}, NOW)
    row = result["rows"][0]
    assert row["action"] == RETAIN
    assert "unknown age is never treated as an expired record" in row["reason"]


def test_deletion_is_the_strongest_claim_the_plan_makes():
    result = plan([_event("e1", "ACTIVITY", "2020-01-01T00:00:00Z")],
                  {"require_disposition_ref": True}, NOW)
    assert result["rows"][0]["action"] == DELETE_CANDIDATE
    assert "disposition" in result["not_proven"][0]
    assert "disposition-gated" in result["note"]
