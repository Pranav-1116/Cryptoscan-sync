"""Scan trigger / scheduling / incremental tests (spec #10, #11, #12)."""

from __future__ import annotations

from privacy.triggers import (
    event_for_change,
    is_incremental,
    resolve_schedule,
)


def test_interval_schedules():
    s = resolve_schedule("every_5_minutes")
    assert s.kind == "interval" and s.interval_s == 300
    s = resolve_schedule("weekly")
    assert s.kind == "interval" and s.interval_s == 604800


def test_on_change_subscribes_to_events():
    s = resolve_schedule("on_change")
    assert s.kind == "event"
    assert "certificate.changed" in s.events
    assert "asset.created" in s.events


def test_unknown_cadence_defaults_to_manual():
    s = resolve_schedule("monthly")
    assert s.kind == "manual"


def test_event_for_change_maps_to_scans():
    assert event_for_change("certificate.changed") == ("crypto", "certificate")
    assert event_for_change("asset.created") == ("discovery",)
    assert event_for_change("firmware.changed") == ("hardware", "vendor")


def test_incremental_requires_baseline():
    d = is_incremental("standard", baseline_at=None, now=1000)
    assert d.incremental is False
    assert "no baseline" in d.reason


def test_incremental_rejects_old_baseline():
    now = 1_000_000.0
    d = is_incremental("standard", baseline_at=now - 10 * 86400, now=now,
                       changed_assets=["a"])
    assert d.incremental is False
    assert "too old" in d.reason


def test_incremental_fresh_with_changed():
    now = 1_000_000.0
    d = is_incremental("standard", baseline_at=now - 3600, now=now,
                       changed_assets=["asset-9"])
    assert d.incremental is True
    assert d.changed_assets == ["asset-9"]
