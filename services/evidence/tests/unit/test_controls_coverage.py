"""Auditor zip gains controls-coverage.json from policy evaluations."""

from __future__ import annotations

import io
import json
import zipfile

from evidence.pack.audit_zip import build_audit_zip, controls_coverage


def _pack():
    def record(rules):
        return {"algorithm": "RSA-2048", "file_path": "src/a.py", "policy_evaluation": {"rules_evaluated": rules}}

    return {
        "pack_format": "cryptoscan-evidence",
        "records": [
            record(
                [
                    {"rule_id": "PQC-001", "standard_reference": "CNSA 2.0", "evaluation_result": "FAIL"},
                    {"rule_id": "KEY-002", "standard_reference": "NIST SP 800-57", "evaluation_result": "PASS"},
                ]
            ),
            record([{"rule_id": "PQC-001", "standard_reference": "CNSA 2.0", "evaluation_result": "FAIL"}]),
            record([{"rule_id": "INTERNAL-9", "evaluation_result": "PASS"}]),  # no standard -> Internal
            {"algorithm": "AES-256", "file_path": "src/b.py"},  # no evaluation at all
        ],
    }


def test_controls_coverage_rollup():
    coverage = controls_coverage(_pack())
    standards = coverage["standards"]
    assert standards["CNSA 2.0"] == {"pass": 0, "fail": 2, "requirements": ["PQC-001"]}
    assert standards["NIST SP 800-57"] == {"pass": 1, "fail": 0, "requirements": ["KEY-002"]}
    assert standards["Internal"] == {"pass": 1, "fail": 0, "requirements": ["INTERNAL-9"]}
    assert coverage["standard_count"] == 3
    assert coverage["totals"] == {"pass": 2, "fail": 2}
    assert "policy engine" in coverage["note"]


def test_zip_contains_controls_coverage_file():
    payload = build_audit_zip(evidence_pack=_pack())
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = archive.namelist()
        assert "controls-coverage.json" in names
        data = json.loads(archive.read("controls-coverage.json"))
    assert data["standards"]["CNSA 2.0"]["fail"] == 2
    assert data["totals"]["fail"] == 2


def test_controls_coverage_honest_when_empty():
    coverage = controls_coverage({"records": [{"algorithm": "AES-256"}]})
    assert coverage["standards"] == {}
    assert coverage["standard_count"] == 0
    assert coverage["totals"] == {"pass": 0, "fail": 0}
    payload = build_audit_zip(evidence_pack={"records": []})
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert "controls-coverage.json" in archive.namelist()  # present even when empty
