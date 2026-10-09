"""Reintroduction detection — severity routing + scope matching (audit 69 / GAP-023).

A retired algorithm that reappears is a broken promise, not a new finding;
these tests pin the scopes, the severity routing and the refusal to match
malformed registry rows.
"""

from __future__ import annotations

from remediation.reintroduction import CRITICAL, HIGH, MEDIUM, detect_reintroductions

RETIRE = {
    "id": "ret-1",
    "algorithm": "DES",
    "scope": "FILE",
    "file_path": "src/pay/CardCipher.java",
    "retired_by": "auditor-1",
    "reason": "replaced with AES-256-GCM (task t-1)",
}


def _f(algorithm, file_path="src/pay/CardCipher.java", status="PASS", line=42, **extra):
    return {"algorithm": algorithm, "file_path": file_path, "line_number": line,
            "compliance_status": status, "is_hardcoded_key": False, **extra}


def test_clean_scan_produces_no_detections():
    assert detect_reintroductions([RETIRE], [_f("AES-256-GCM")]) == []


def test_file_scope_requires_the_location():
    # DES reappears — but in a different file; FILE scope does not fire
    assert detect_reintroductions([RETIRE], [_f("DES", file_path="src/other.java")]) == []
    # and at the retired location it does
    out = detect_reintroductions([RETIRE], [_f("DES", status="FAIL")])
    assert len(out) == 1
    assert out[0]["severity"] == CRITICAL
    assert out[0]["matched_sites"][0]["line_number"] == 42


def test_hardcoded_key_is_critical_even_when_status_passes():
    out = detect_reintroductions([RETIRE], [_f("DES", is_hardcoded_key=True)])
    assert out[0]["severity"] == CRITICAL


def test_severity_routing():
    assert detect_reintroductions([RETIRE], [_f("DES", status="FAIL")])[0]["severity"] == CRITICAL
    assert detect_reintroductions([RETIRE], [_f("DES", status="WARN")])[0]["severity"] == HIGH
    assert detect_reintroductions([RETIRE], [_f("DES", status="PASS")])[0]["severity"] == MEDIUM
    # worst match wins when several sites reintroduce at once
    out = detect_reintroductions(
        [RETIRE], [_f("DES", status="WARN", line=1), _f("DES", status="FAIL", line=2)])
    assert out[0]["severity"] == CRITICAL
    assert len(out[0]["matched_sites"]) == 2


def test_algorithm_scope_fires_anywhere():
    broad = {**RETIRE, "id": "ret-2", "scope": "ALGORITHM", "file_path": None}
    out = detect_reintroductions([broad], [_f("DES", file_path="anywhere/else.java")])
    assert len(out) == 1 and out[0]["scope"] == "ALGORITHM"


def test_asset_scope_uses_the_linkage():
    scoped = {**RETIRE, "id": "ret-3", "scope": "ASSET", "file_path": None,
              "asset_id": "asset-9"}
    # evidence linked to a different asset does not fire
    assert detect_reintroductions([scoped], [_f("DES", asset_ids=["asset-1"])]) == []
    # evidence linked to the retired asset fires — file is irrelevant
    out = detect_reintroductions([scoped], [_f("DES", file_path="x.java", asset_ids=["asset-9"])])
    assert len(out) == 1 and out[0]["scope"] == "ASSET"


def test_malformed_rows_never_match_everything():
    # ASSET scope without an asset id would otherwise match any DES evidence
    bad = {**RETIRE, "scope": "ASSET", "asset_id": None}
    assert detect_reintroductions([bad], [_f("DES")]) == []
    # unknown scope never fires
    bad2 = {**RETIRE, "scope": "EVERYTHING"}
    assert detect_reintroductions([bad2], [_f("DES")]) == []


def test_detection_carries_the_promise_context():
    out = detect_reintroductions([RETIRE], [_f("DES", status="FAIL")])[0]
    assert out["retirement_id"] == "ret-1"
    assert out["retired_by"] == "auditor-1"
    assert "task t-1" in out["reason"]
