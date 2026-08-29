"""CI gate policy profiles + PR-comment rendering (Week 49-50)."""

from __future__ import annotations

import copy

import pytest

from drift.core.gate import apply_gate_profile, evaluate_gate, render_pr_comment


def _finding(algorithm="MD5", purpose="HASHING", status="FAIL", **extra):
    row = {
        "algorithm": algorithm,
        "purpose": purpose,
        "mode": None,
        "key_size": None,
        "file_path": "src/Pay.java",
        "line_number": 7,
        "compliance_status": status,
        "is_hardcoded_key": False,
    }
    row.update(extra)
    return row


def _weak():
    return _finding("DES", purpose="ENCRYPTION")


def _hardcoded():
    return _finding("AES-256-GCM", purpose="ENCRYPTION", status="PASS", is_hardcoded_key=True)


# --------------------------------------------------------------------------- #
# profiles
# --------------------------------------------------------------------------- #

def test_standard_is_unchanged_and_default():
    gate = evaluate_gate([_weak()], [])
    adjusted = apply_gate_profile(gate, "standard")
    assert adjusted["decision"] == gate["decision"] == "FAIL"
    assert adjusted["profile"] == "standard"
    assert apply_gate_profile(gate) == adjusted


def test_strict_promotes_warnings_to_blocking():
    # MD5 hashing is a warning under standard semantics
    gate = evaluate_gate([_finding("MD5")], [])
    assert gate["decision"] == "WARN" and len(gate["blocking"]) == 0
    strict = apply_gate_profile(gate, "strict")
    assert strict["decision"] == "FAIL"
    assert len(strict["blocking"]) == 1 and not strict["warnings"]
    assert strict["blocking"][0]["code"] == "WEAK_HASH"


def test_lenient_blocks_only_hardcoded_keys_and_downgrades():
    both = evaluate_gate([_weak(), _hardcoded()], [])
    assert both["decision"] == "FAIL" and len(both["blocking"]) == 2
    lenient = apply_gate_profile(both, "lenient")
    codes = {item["code"] for item in lenient["blocking"]}
    assert codes == {"HARDCODED_KEY"}  # WEAK_CRYPTO demoted to a warning
    assert len(lenient["warnings"]) == 1
    assert lenient["decision"] == "FAIL"

    downgrade = evaluate_gate([], [{"change_type": "DOWNGRADED", "severity": "CRITICAL"}])
    # downgrades block under every posture (they used to fall through all
    # gate branches entirely — a CRITICAL downgrade never blocked CI)
    for profile in ("standard", "strict", "lenient"):
        assert apply_gate_profile(downgrade, profile)["decision"] == "FAIL"


def test_profile_never_mutates_input_and_rejects_unknown():
    gate = evaluate_gate([_finding("MD5")], [])
    snapshot = copy.deepcopy(gate)
    apply_gate_profile(gate, "strict")
    apply_gate_profile(gate, "lenient")
    assert gate == snapshot
    with pytest.raises(ValueError):
        apply_gate_profile(gate, "yolo")


def test_pass_stays_pass_under_all_profiles():
    gate = evaluate_gate([_finding("AES-256-GCM", purpose="ENCRYPTION", status="PASS")], [])
    assert gate["decision"] == "PASS"
    for profile in ("standard", "strict", "lenient"):
        assert apply_gate_profile(gate, profile)["decision"] == "PASS"


# --------------------------------------------------------------------------- #
# PR comment
# --------------------------------------------------------------------------- #

def test_pr_comment_shape_and_escaping():
    gate = evaluate_gate([_weak(), _hardcoded(), _finding("MD5")], [])
    strict = apply_gate_profile(gate, "strict")
    comment = render_pr_comment(strict)
    assert comment.startswith("### ❌ CryptoScan gate: FAIL")
    assert "profile `strict`" in comment
    assert "| `WEAK_CRYPTO`" in comment and "src/Pay.java:7" in comment
    assert "_Deterministic evaluation" in comment


def test_pr_comment_escapes_pipes_and_caps_rows():
    nasty = evaluate_gate(
        [_finding("DES", purpose="ENCRYPTION", file_path="a|b.py", line_number=1)], []
    )
    comment = render_pr_comment(nasty)
    assert "a\\|b.py" in comment  # markdown table stays intact
    gate = {"decision": "PASS", "summary": "0 blocking", "scan_id": "s1", "blocking": []}
    assert "✅" in render_pr_comment(gate) and "Blocking" not in render_pr_comment(gate)
