"""Change classification taxonomy (audit 68 P0#3, round 29)."""

from __future__ import annotations

from universal_crypto.live.change_taxonomy import (classify_change,
                                                   classify_timeline)
from universal_crypto.models import CryptoEventType


def _event(event_type: str, payload: dict | None = None, asset: str = "a1") -> dict:
    return {"event_type": event_type, "asset_id": asset, "payload": payload or {}}


def test_every_journal_event_type_is_classified():
    for et in CryptoEventType:
        entry = classify_change(_event(et.value))
        assert entry["change_class"], et
        assert entry["impact"] >= 0
        assert entry["direction"]
        assert entry["description"]


def test_event_level_classes():
    assert classify_change(_event("ALGORITHM_DETECTED"))["change_class"] == "DISCOVERY"
    assert classify_change(_event("CERT_RENEWED"))["change_class"] == "OPERATIONAL"
    assert classify_change(_event("CERT_REVOKED"))["direction"] == "DETERIORATION"
    assert classify_change(_event("KEY_ROTATED"))["direction"] == "IMPROVEMENT"
    assert classify_change(_event("UNKNOWN_CRYPTO_OPERATION"))["change_class"] == "ALERT"


def test_unrecognized_event_type_is_alert_never_guessed():
    entry = classify_change(_event("SOMETHING_NEW"))
    assert entry["change_class"] == "ALERT"
    assert entry["direction"] == "UNKNOWN"
    assert "never guessed" in entry["description"]


def test_payload_key_size_direction():
    shrink = classify_change(_event("KEY_ROTATED",
                                    {"old_key_size": 2048, "new_key_size": 1024}))
    assert shrink["direction"] == "DETERIORATION"
    grow = classify_change(_event("KEY_ROTATED",
                                  {"old_key_size": 1024, "new_key_size": 3072}))
    assert grow["direction"] == "IMPROVEMENT"
    same = classify_change(_event("KEY_ROTATED",
                                  {"old_key_size": 2048, "new_key_size": 2048}))
    assert same["direction"] == "NEUTRAL"


def test_payload_algorithm_designation_direction():
    # DES (DISALLOWED) -> AES-256 (ALLOWED) is an improvement
    better = classify_change(_event("ALGORITHM_REMOVED",
                                    {"old_algorithm": "DES",
                                     "new_algorithm": "AES-256-GCM"}))
    assert better["direction"] == "IMPROVEMENT"
    # the reverse is a deterioration
    worse = classify_change(_event("ALGORITHM_DETECTED",
                                   {"old_algorithm": "AES-256-GCM",
                                    "new_algorithm": "DES"}))
    assert worse["direction"] == "DETERIORATION"


def test_timeline_rollup_counts_and_unknown_types():
    events = [
        _event("ALGORITHM_DETECTED", asset="a"),
        _event("ALGORITHM_DETECTED", asset="b"),
        _event("CERT_EXPIRING", asset="a"),
        _event("WEIRD_THING", asset="a"),
    ]
    summary = classify_timeline(events)
    assert summary["event_count"] == 4
    assert summary["by_change_class"] == {"DISCOVERY": 2, "OPERATIONAL": 1, "ALERT": 1}
    assert summary["by_direction"]["DETERIORATION"] == 1
    assert summary["unrecognized_event_types"] == ["WEIRD_THING"]
    # the classified events keep their original fields
    assert summary["events"][0]["asset_id"] == "a"
    assert summary["events"][0]["classification"]["change_class"] == "DISCOVERY"
    assert "not risk scores" in summary["impact_note"]


def test_empty_timeline():
    summary = classify_timeline([])
    assert summary["event_count"] == 0
    assert summary["by_change_class"] == {}
    assert summary["unrecognized_event_types"] == []
