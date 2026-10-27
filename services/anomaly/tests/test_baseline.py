"""Deterministic posture baseline + drift tests (no AI/ML)."""

from __future__ import annotations

import pytest

from anomaly.baseline import (
    baseline_from_dict,
    build_baseline,
    compare_baseline,
)


def _find(algo, size=None, hard=False):
    return {"algorithm": algo, "key_size": size, "is_hardcoded_key": hard,
            "file_path": "x.java", "confidence": "HIGH"}


def test_baseline_fingerprint_deterministic_and_stable():
    fs = [_find("AES", 256), _find("RSA", 2048)]
    b1 = build_baseline(fs)
    b2 = build_baseline([dict(f) for f in fs])
    assert b1.digest == b2.digest
    assert b1.weak_findings_total == 0  # AES-256 + RSA-2048 are compliant


def test_weak_algorithms_detected():
    b = build_baseline([_find("DES", 56), _find("AES", 256)])
    assert "DES" in b.weak_algorithms
    assert b.weak_findings_total == 1


def test_rsa_below_floor_flagged():
    b = build_baseline([_find("RSA", 1024)])
    assert any(w.startswith("RSA<") for w in b.weak_algorithms)
    assert b.min_key_size == 1024


def test_no_drift_when_same_posture():
    base = build_baseline([_find("AES", 256)])
    report = compare_baseline(base, [_find("AES", 256), _find("AES", 256)])
    assert report.drifted is False
    assert report.drifts == []


def test_new_weak_algorithm_is_high_drift():
    base = build_baseline([_find("AES", 256)])
    report = compare_baseline(base, [_find("AES", 256), _find("DES", 56)])
    assert report.drifted
    kinds = {d.kind: d for d in report.drifts}
    assert "new_weak_algorithm" in kinds
    assert kinds["new_weak_algorithm"].severity == "HIGH"


def test_key_size_regression_detected():
    base = build_baseline([_find("RSA", 2048)])
    report = compare_baseline(base, [_find("RSA", 1024)])
    kinds = {d.kind for d in report.drifts}
    assert "key_size_regression" in kinds


def test_weak_count_increase_medium():
    base = build_baseline([_find("DES", 56)])
    report = compare_baseline(base, [_find("DES", 56), _find("DES", 56)])
    kinds = {d.kind: d.severity for d in report.drifts}
    assert kinds.get("weak_count_increase") == "MEDIUM"


def test_hardcoded_key_increase():
    base = build_baseline([_find("AES", 256, hard=False)])
    report = compare_baseline(base, [_find("AES", 256, hard=True)])
    assert any(d.kind == "hardcoded_keys_increased" for d in report.drifts)


def test_improvement_is_not_drift():
    # DES removed, AES present -> weak count drops; should NOT be drift
    base = build_baseline([_find("DES", 56)])
    report = compare_baseline(base, [_find("AES", 256)])
    assert report.drifted is False


def test_tampered_baseline_rejected():
    b = build_baseline([_find("DES", 56)]).to_dict()
    b["weak_findings_total"] = 999  # alter without recomputing digest
    with pytest.raises(ValueError):
        baseline_from_dict(b)


def test_roundtrip_baseline_dict():
    b = build_baseline([_find("DES", 56), _find("RSA", 1024)])
    restored = baseline_from_dict(b.to_dict())
    assert restored.digest == b.digest
    assert set(restored.weak_algorithms) == set(b.weak_algorithms)
