"""The checked-in scan-result schema must be the real contract.

`scanner/output/schema/scan_result_schema.json` is generated from the pydantic
`ScanResult` model. These tests keep the committed file in sync with the code
and prove that real scanner output validates against it.
"""

from __future__ import annotations

import json
from pathlib import Path

from scanner.models.scan_result import ScanResult
from scanner.output.json_schema import is_valid_scan_result

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "output" / "schema" / "scan_result_schema.json"
)


def _demo_repo() -> Path:
    root = Path(__file__).resolve().parents[3]
    return root / "demo" / "vulnerable-app"


def test_committed_schema_matches_model():
    committed = json.loads(SCHEMA_PATH.read_text())
    generated = ScanResult.model_json_schema()
    assert committed == generated, (
        "scanner/output/schema/scan_result_schema.json is out of sync with the "
        "ScanResult model — regenerate it and commit the update"
    )


def test_schema_declares_required_contract_fields():
    schema = json.loads(SCHEMA_PATH.read_text())
    for field in ("scan_id", "scanner_id", "scan_target", "statistics", "findings", "status"):
        assert field in schema["properties"], f"missing {field} in schema properties"
    defs = schema["$defs"]
    assert "RawFinding" in defs and "SourceLocation" in defs and "CryptoInfo" in defs


def test_real_scan_output_round_trips_through_schema():
    from scanner.core.scanner import CryptoScanner

    result = CryptoScanner().scan(root_path=_demo_repo())
    result.finalize()

    payload = json.loads(result.model_dump_json())
    # Structural validation (lightweight, no jsonschema dependency)
    assert is_valid_scan_result(payload), "scanner output failed structural validation"
    # Full pydantic round-trip: JSON -> model must reconstruct every finding.
    rebuilt = ScanResult.model_validate(payload)
    assert len(rebuilt.findings) == len(result.findings)
    assert rebuilt.statistics.total_findings == len(result.findings)
    assert rebuilt.scan_id == result.scan_id


def test_invalid_payload_rejected_by_structural_validator():
    assert not is_valid_scan_result({"unexpected": True})
    assert not is_valid_scan_result({"scan_id": "s", "scanner_id": "x", "findings": [{"no": "fields"}]})
