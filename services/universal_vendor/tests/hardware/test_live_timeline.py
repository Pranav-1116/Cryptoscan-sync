"""Historical hardware timeline (§16) — journal + point-in-time state
reconstruction ('show hardware state at 2026-08-31 12:00')."""

from __future__ import annotations

from universal_vendor.hardware.live import HardwareTimeline

T0 = "2026-08-31T10:00:00+00:00"
T1 = "2026-08-31T12:30:00+00:00"
T2 = "2026-08-31T13:00:00+00:00"
T3 = "2026-08-31T14:10:00+00:00"


def _discovered(t=T0, asset="srv-1"):
    return {"event_type": "HARDWARE_DISCOVERED", "asset_id": asset,
            "manufacturer": "Dell", "model": "R760", "observed_at": t}


def _bios(t, version, asset="srv-1"):
    return {"event_type": "BIOS_CHANGED", "asset_id": asset,
            "component": "BIOS", "version": version, "observed_at": t}


def _tpm(t, present, asset="srv-1"):
    return {"event_type": "TPM_AVAILABLE" if present else "TPM_UNAVAILABLE",
            "asset_id": asset, "tpm": {"present": present}, "observed_at": t}


def _journal():
    tl = HardwareTimeline()
    tl.record(_discovered())
    tl.record(_bios(T1, "2.18"))
    tl.record(_tpm(T2, True))
    tl.record(_bios(T3, "2.19"))
    return tl


def test_journal_append_and_events():
    tl = _journal()
    assert tl.count() == 4
    assert tl.count("srv-1") == 4
    assert tl.count("other") == 0
    assert tl.events(asset_id="srv-1")[0]["event_type"] == "HARDWARE_DISCOVERED"


def test_state_at_point_in_time_reconstruction():
    tl = _journal()
    # state as of 12:45 — after BIOS 2.18 (12:30), before the TPM (13:00)
    noon = tl.state_at("srv-1", "2026-08-31T12:45:00+00:00")
    assert noon["firmware"]["BIOS"] == "2.18"
    assert noon["tpm"] is None
    # state as of 13:30 — TPM present, BIOS still 2.18
    later = tl.state_at("srv-1", "2026-08-31T13:30:00+00:00")
    assert later["tpm"]["present"] is True
    assert later["firmware"]["BIOS"] == "2.18"
    # final state — BIOS 2.19
    final = tl.state_at("srv-1", "2026-08-31T15:00:00+00:00")
    assert final["firmware"]["BIOS"] == "2.19"


def test_state_at_before_first_event_is_none():
    tl = _journal()
    assert tl.state_at("srv-1", "2026-08-31T09:00:00+00:00") is None


def test_state_at_does_not_see_future_events():
    tl = HardwareTimeline()
    tl.record(_discovered(T0))
    tl.record(_tpm(T3, True))
    at = tl.state_at("srv-1", T2)
    assert at["tpm"] is None  # TPM event at 14:10 must not leak into 13:00


def test_timeline_human_readable_summaries():
    tl = _journal()
    entries = tl.timeline("srv-1")
    assert entries[0]["summary"] == "Server discovered: srv-1"
    assert any("BIOS changed" in e["summary"] and "2.19" in e["summary"] for e in entries)
    assert any("TPM available" in e["summary"] for e in entries)
    assert entries == sorted(entries, key=lambda e: e["timestamp"])


def test_rebuild_state_matches_live_replay():
    tl = _journal()
    rebuilt = tl.rebuild_state()
    assert rebuilt["srv-1"]["firmware"]["BIOS"] == "2.19"
    assert rebuilt["srv-1"]["tpm"]["present"] is True
    assert rebuilt["srv-1"]["manufacturer"] == "Dell"
