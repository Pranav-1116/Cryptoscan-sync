"""Deterministic certificate expiry calendar / SLA buckets."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from network_scanner.certificates.expiry_calendar import (
    build_expiry_calendar,
    days_remaining,
    tier_for_days,
)

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)


def _cert(days: int | None, subject: str = "cn", *, renewed: str | None = None):
    payload = {"subject": subject, "fingerprint_sha256": f"fp-{subject}"}
    if days is not None:
        payload["not_after"] = (NOW + timedelta(days=days)).isoformat()
    if renewed:
        payload["renewal_status"] = renewed
    return payload


def test_tier_boundaries():
    assert tier_for_days(-1)[0] == "expired"
    assert tier_for_days(0)[0] == "critical"
    assert tier_for_days(7)[0] == "critical"
    assert tier_for_days(8)[0] == "warning"
    assert tier_for_days(30)[0] == "warning"
    assert tier_for_days(31)[0] == "scheduled"
    assert tier_for_days(90)[0] == "scheduled"
    assert tier_for_days(91)[0] == "healthy"
    assert tier_for_days(None)[0] == "unknown"


def test_days_remaining_computed_from_not_after():
    c = _cert(10)
    assert days_remaining(c, now=NOW) == 10
    assert days_remaining(_cert(None), now=NOW) is None


def test_calendar_buckets_and_counts():
    cal = build_expiry_calendar([
        _cert(-3, "exp"),
        _cert(2, "crit"),
        _cert(20, "warn"),
        _cert(60, "sched"),
        _cert(200, "ok"),
        _cert(None, "unk"),
    ], now=NOW)
    assert cal["counts"] == {
        "expired": 1, "critical": 1, "warning": 1,
        "scheduled": 1, "healthy": 1, "unknown": 1,
    }
    assert cal["total_tracked"] == 6
    assert cal["actionable_count"] == 3  # expired + critical + warning
    assert cal["buckets"]["critical"][0]["severity"] == "CRITICAL"


def test_critical_sorted_most_urgent_first():
    cal = build_expiry_calendar([_cert(7, "a"), _cert(1, "b")], now=NOW)
    crit = cal["buckets"]["critical"]
    assert [c["subject"] for c in crit] == ["b", "a"]


def test_stored_days_used_when_no_not_after():
    # no not_after, but a stored days_until_expiry => still bucketed
    c = {"subject": "legacy", "days_until_expiry": 5}
    assert days_remaining(c, now=NOW) == 5
    cal = build_expiry_calendar([c], now=NOW)
    assert cal["counts"]["critical"] == 1
