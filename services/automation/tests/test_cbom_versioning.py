"""Deterministic live CBOM versioning tests (no AI/ML)."""

from __future__ import annotations

from datetime import datetime, timezone

from automation.cbom_versioning import LiveCbom

NOW = datetime(2026, 9, 3, tzinfo=timezone.utc)


def _obs(*pairs):
    out = []
    for comp_id, algo, size in pairs:
        out.append({"component_id": comp_id, "algorithm": algo, "key_size": size,
                    "library": "lib", "library_version": "1.0"})
    return out


def test_first_update_creates_version_1():
    cbom = LiveCbom()
    diff = cbom.update(_obs(("a", "AES", 256)), now=NOW)
    assert diff.changed is True and diff.new_version == 1
    assert cbom.latest().component_count == 1


def test_unchanged_state_no_new_version():
    cbom = LiveCbom()
    cbom.update(_obs(("a", "AES", 256)), now=NOW)
    # same observations in different order -> same fingerprint
    diff = cbom.update(list(reversed(_obs(("a", "AES", 256)))), now=NOW)
    assert diff.changed is False and cbom.version_count == 1


def test_new_component_added():
    cbom = LiveCbom()
    cbom.update(_obs(("a", "AES", 256)), now=NOW)
    diff = cbom.update(_obs(("a", "AES", 256), ("b", "RSA", 2048)), now=NOW)
    d = diff.as_dict()
    assert diff.changed is True and diff.new_version == 2
    assert d["added_count"] == 1 and diff.added[0]["id"] == "b"


def test_component_removed():
    cbom = LiveCbom()
    cbom.update(_obs(("a", "AES", 256), ("b", "RSA", 2048)), now=NOW)
    diff = cbom.update(_obs(("a", "AES", 256)), now=NOW)
    assert diff.as_dict()["removed_count"] == 1 and diff.removed[0]["id"] == "b"


def test_algorithm_change_detected_as_remove_and_add():
    cbom = LiveCbom()
    cbom.update(_obs(("a", "RSA", 2048)), now=NOW)
    # migrated to ECDSA
    diff = cbom.update([{"component_id": "a", "algorithm": "ECDSA", "key_size": 256,
                         "library": "lib", "library_version": "2.0"}], now=NOW)
    assert diff.changed is True
    assert diff.added[0]["algorithm"] == "ECDSA"
    assert diff.removed[0]["algorithm"] == "RSA"


def test_version_chain_fingerprints():
    cbom = LiveCbom()
    cbom.update(_obs(("a", "AES", 256)), now=NOW)
    cbom.update(_obs(("a", "AES", 256), ("b", "RSA", 2048)), now=NOW)
    history = cbom.history()
    assert history[1]["parent_fingerprint"] == history[0]["fingerprint"]


def test_deterministic_fingerprint():
    a = LiveCbom()
    a.update(_obs(("a", "AES", 256), ("b", "RSA", 2048)), now=NOW)
    b = LiveCbom()
    b.update(list(reversed(_obs(("a", "AES", 256), ("b", "RSA", 2048)))), now=NOW)
    assert a.latest().fingerprint == b.latest().fingerprint
