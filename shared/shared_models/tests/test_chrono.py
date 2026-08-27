"""Tests for shared_models.chrono — the shared datetime contract."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from shared_models.chrono import aware, epoch_seconds, iso_utc, parse_iso, utcnow


def test_utcnow_is_aware_utc():
    now = utcnow()
    assert now.tzinfo is not None
    assert now.utcoffset().total_seconds() == 0


def test_aware_assumes_utc_for_naive():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    fixed = aware(naive)
    assert fixed.tzinfo is timezone.utc
    # Value preserved, only the zone added.
    assert fixed.replace(tzinfo=None) == naive


def test_aware_passes_none_through():
    assert aware(None) is None


def test_aware_leaves_aware_values_untouched():
    now = utcnow()
    assert aware(now) is now


def test_iso_utc_round_trip():
    stamp = iso_utc()
    parsed = parse_iso(stamp)
    assert parsed is not None and parsed.tzinfo is not None
    assert abs((parsed - utcnow()).total_seconds()) < 5


def test_parse_iso_handles_z_suffix_and_naive():
    assert parse_iso("2026-08-27T04:00:00Z").tzinfo is not None
    assert parse_iso("2026-08-27T04:00:00").tzinfo is not None  # assumed UTC


def test_parse_iso_invalid_and_empty():
    assert parse_iso(None) is None
    assert parse_iso("") is None
    assert parse_iso("not-a-date") is None


def test_epoch_seconds_utc_normalised():
    dt = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert epoch_seconds(dt) == 0.0
    later = dt + timedelta(days=1)
    assert epoch_seconds(later) == 86400.0
