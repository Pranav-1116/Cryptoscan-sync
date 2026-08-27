"""Discovery → scheduler registration: found endpoints enter the due rotation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from network_scanner.core.scheduler import due_targets, is_due
from network_scanner.discovery.registration import build_target_records, register_targets


class FakeRepo:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def upsert_target(self, endpoint, **kwargs):
        self.calls.append((endpoint, kwargs))


def test_build_target_records_dedupes_and_drops_blanks():
    records = build_target_records(["10.0.0.1:443", "10.0.0.1:443", "  ", "10.0.0.2:8443"])
    assert [record["endpoint"] for record in records] == ["10.0.0.1:443", "10.0.0.2:8443"]


def test_build_target_records_are_due_immediately():
    now = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
    records = build_target_records(["10.0.0.1:443"], now=now)
    assert records[0]["next_scan_time"] == now.isoformat()
    # the scheduler agrees: these targets are due right away
    assert is_due(records[0], now=now) is True
    # ...and not due before they exist
    assert is_due(records[0], now=now - timedelta(seconds=1)) is False


def test_build_target_records_frequency_normalization():
    now = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
    assert build_target_records(["a:443"], scan_frequency="HOURLY", now=now)[0]["scan_frequency"] == "hourly"
    assert build_target_records(["a:443"], scan_frequency="whenever", now=now)[0]["scan_frequency"] == "daily"
    assert build_target_records(["a:443"], scan_frequency=None, now=now)[0]["scan_frequency"] == "daily"


def test_build_target_records_disabled_and_source():
    records = build_target_records(["a:443"], enabled=False)
    assert records[0]["enabled"] is False
    assert records[0]["source"] == "subnet-discovery"
    assert is_due(records[0]) is False  # disabled targets never come due


def test_build_target_records_empty():
    assert build_target_records([]) == []
    assert build_target_records(None) == []


def test_register_targets_new_vs_updated():
    repo = FakeRepo()
    result = register_targets(
        repo,
        ["10.0.0.1:443", "10.0.0.2:443", "10.0.0.1:443"],
        scan_frequency="weekly",
        existing={"10.0.0.1:443"},
    )
    assert result["registered"] == 1
    assert result["updated"] == 1
    assert result["total"] == 2
    assert result["scan_frequency"] == "weekly"
    assert result["endpoints"] == ["10.0.0.1:443", "10.0.0.2:443"]
    # the repo saw each endpoint exactly once, with datetime objects
    assert [endpoint for endpoint, _kw in repo.calls] == ["10.0.0.1:443", "10.0.0.2:443"]
    for _endpoint, kwargs in repo.calls:
        assert isinstance(kwargs["next_scan_time"], datetime)
        assert kwargs["scan_frequency"] == "weekly"
        assert kwargs["enabled"] is True


def test_register_targets_empty_endpoints():
    repo = FakeRepo()
    result = register_targets(repo, [])
    assert result == {
        "registered": 0,
        "updated": 0,
        "total": 0,
        "scan_frequency": "daily",
        "endpoints": [],
    }
    assert repo.calls == []


def test_registered_records_flow_into_due_rotation():
    """The loop closes: sweep output -> records -> due_targets picks them up."""
    now = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
    records = build_target_records(["10.0.0.1:443", "10.0.0.2:8443"], scan_frequency="daily", now=now)
    due = due_targets(records, now=now)
    assert [item["endpoint"] for item in due] == ["10.0.0.1:443", "10.0.0.2:8443"]
    # after a day passes without a rescan, they are due again (daily frequency)
    later = now + timedelta(days=1, seconds=1)
    assert all(is_due(record, now=later) for record in records)
