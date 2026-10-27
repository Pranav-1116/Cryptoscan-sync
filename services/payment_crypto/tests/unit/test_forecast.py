"""Expiry forecasting: buckets, rotation calendar, PAY-015, undated honesty."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from payment_crypto.forecast import ExpiryForecaster, bucket

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def _key(key_id: str, days: int | None) -> dict:
    return {"key_id": key_id,
            "expiry_at": (NOW + timedelta(days=days)).isoformat() if days is not None else None}


def test_bucket_boundaries():
    assert bucket(-1) == "EXPIRED"
    assert bucket(0) == "EXPIRED"          # expires today = already dead for planning
    assert bucket(1) == "CRITICAL_7D"
    assert bucket(7) == "CRITICAL_7D"
    assert bucket(8) == "WARNING_30D"
    assert bucket(30) == "WARNING_30D"
    assert bucket(31) == "NOTICE_90D"
    assert bucket(91) == "OK"


def test_forecast_buckets_and_undated_counted_honestly():
    report = ExpiryForecaster(now=NOW).forecast([
        _key("K-DEAD", -2), _key("K-SOON", 5), _key("K-MONTH", 25),
        _key("K-QUARTER", 80), _key("K-LATER", 200), _key("K-NODATE", None),
    ])
    assert report["by_status"] == {"EXPIRED": 1, "CRITICAL_7D": 1, "WARNING_30D": 1, "NOTICE_90D": 1, "OK": 1}
    assert report["undated_items"] == 1          # counted, never guessed
    assert report["upcoming_count"] == 3         # 0..90d
    assert [item["reference"] for item in report["upcoming"]] == ["K-SOON", "K-MONTH", "K-QUARTER"]  # expired is not upcoming


def test_pay015_rotation_without_scheduled_ceremony():
    report = ExpiryForecaster(now=NOW).forecast(
        [_key("ZMK-NEEDS-CEREMONY", 30), _key("ZMK-PLANNED", 30)],
        ceremonies=[{"key_id": "ZMK-PLANNED", "held_at": (NOW + timedelta(days=10)).isoformat()}],
    )
    findings = report["findings"]
    assert [finding["key_id"] for finding in findings] == ["ZMK-NEEDS-CEREMONY"]
    assert findings[0]["rule_id"] == "PAY-015"
    assert findings[0]["evidence"]["days_left"] == 30
    # a past ceremony does NOT cover the upcoming rotation
    past = ExpiryForecaster(now=NOW).forecast(
        [_key("ZMK-ONLY-PAST", 30)],
        ceremonies=[{"key_id": "ZMK-ONLY-PAST", "held_at": (NOW - timedelta(days=300)).isoformat()}],
    )
    assert [finding["key_id"] for finding in past["findings"]] == ["ZMK-ONLY-PAST"]


def test_certificates_share_the_calendar():
    report = ExpiryForecaster(now=NOW).forecast(
        [_key("K-1", 10)],
        [{"subject": "CN=api.bank.example", "not_after": (NOW + timedelta(days=12)).isoformat()},
         {"subject": "CN=legacy", "not_after": None}],
    )
    kinds = {item["kind"] for item in report["upcoming"]}
    assert kinds == {"PAYMENT_KEY", "CERTIFICATE"}
    assert report["undated_items"] == 1
    weeks = report["rotation_calendar"]
    assert list(weeks.values())[0] == {"payment_keys": 1, "certificates": 1}


def test_rotation_calendar_groups_by_iso_week():
    monday = NOW - timedelta(days=NOW.weekday())  # 2026-08-31 is a Monday? compute
    report = ExpiryForecaster(now=NOW).forecast([
        _key("K-A", 1), _key("K-B", 3),  # same ISO week as NOW
        _key("K-C", 40),                  # ~6 weeks out
    ])
    weeks = list(report["rotation_calendar"])
    assert len(weeks) == 2
    assert report["rotation_calendar"][weeks[0]]["payment_keys"] == 2
