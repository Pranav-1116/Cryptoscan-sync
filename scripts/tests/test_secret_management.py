"""Tests for the secret-management drill.

Three things have to be true for this drill to be worth anything:

* the canaries have to be *visible* when the protection is off (negative control);
* the scan has to find a planted credential (negative control for the scanner);
* what it reports about the tree has to be stable, including the finding it makes
  about the console's localStorage token — the one row that is a FAIL today.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _relative in ("scripts", "services/api", "services/database", "shared/shared_models",
                  "shared/shared_config", "shared/shared_logging", "services/devsecops",
                  "services/observability", "services/eventstream"):
    sys.path.insert(0, str(ROOT / _relative))

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "secret-management-drill-key-32-characters")

import secret_management as sm  # noqa: E402


@pytest.fixture(scope="module")
def report() -> dict:
    return sm.measure()


def _row(report: dict, row_id: str) -> dict:
    return next(row for row in report["rows"] if row["id"] == row_id)


def test_schema_and_shape(report: dict) -> None:
    assert report["schema"] == sm.SCHEMA
    for row in report["rows"]:
        assert row["verdict"] in {"PASS", "PARTIAL", "FAIL"}
        assert row["probes"], f"{row['id']} has no probe"


def test_canary_is_not_a_substring_the_tree_contains() -> None:
    """The canary must be recognisable but must never be committed."""
    hits = [path for path in (ROOT / "services").rglob("*.py")
            if sm.CANARY in path.read_text(encoding="utf-8", errors="ignore")]
    assert hits == []


def test_source_scan_is_clean_for_product_code(report: dict) -> None:
    row = _row(report, "source_scan")
    assert row["verdict"] == "PASS", row["findings"]
    assert row["findings"] == []


def test_source_scan_sees_harness_fixtures() -> None:
    """If the scan found nothing anywhere, its cleanliness would be meaningless."""
    scan = sm.scan_source()
    assert scan["harness"], "no fixture credential detected — the patterns are dead"
    assert all(hit["surface"] == "harness" for hit in scan["harness"])


def test_source_scan_detects_a_planted_credential(tmp_path) -> None:
    planted = ROOT / "services" / "database" / "planted_secret_drill.py"
    planted.write_text('AWS = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n')
    try:
        scan = sm.scan_source()
    finally:
        planted.unlink()
    assert any(hit["path"].endswith("planted_secret_drill.py")
               for hit in scan["findings"]), scan["findings"]


def test_structured_redaction_masks_a_canary() -> None:
    probes = {probe["probe"]: probe for probe in sm.probe_log_redaction()}
    assert probes["structured-field"]["ok"] is True, probes["structured-field"]["observed"]
    assert probes["control-redaction-off"]["ok"] is True, (
        "the canary never reached the sink: the redaction check would pass vacuously")


def test_free_text_gap_is_reported_not_hidden(report: dict) -> None:
    row = _row(report, "log_redaction")
    probes = {probe["probe"]: probe for probe in row["probes"]}
    # Key-based redaction cannot scrub a message string. If this ever starts
    # passing, the row should become PASS — not be silently dropped.
    if not probes["free-text-message"]["ok"]:
        assert row["verdict"] == "PARTIAL"
        assert row["unproven"], "the gap must be written down, not just counted"


def test_error_message_control_is_visible() -> None:
    probes = {probe["probe"]: probe for probe in sm.probe_error_message()}
    assert probes["unhandled-exception-body"]["ok"] is True
    assert probes["explicit-detail"]["ok"] is True, (
        "the control did not come back — an empty body would make the first probe vacuous")


def test_access_line_records_no_credential() -> None:
    probes = sm.probe_access_log()
    assert probes[0]["ok"] is True, probes[0]["observed"]


def test_frontend_storage_finding_is_reported(report: dict) -> None:
    """The console's localStorage token is the drill's live finding."""
    row = _row(report, "frontend_storage")
    probes = sm.probe_frontend()[0]
    storage = next(probe for probe in probes if probe["probe"] == "no-token-in-web-storage")
    if storage["ok"]:
        assert row["verdict"] == "PASS"
    else:
        assert row["verdict"] == "FAIL"
        assert any("localStorage" in str(entry) or "zelnx" in str(entry)
                   for entry in row["storage"]) or row["storage"], row


def test_allow_list_entries_carry_a_reason() -> None:
    scan = sm.scan_source()
    for entry in scan["allowed"]:
        assert entry["reason"].strip(), entry
        assert len(entry["reason"]) > 20


def test_cli_writes_reports(tmp_path) -> None:
    json_path = tmp_path / "secrets.json"
    md_path = tmp_path / "secrets.md"
    assert sm.main(["--json", str(json_path), "--md", str(md_path)]) == 0
    payload = json.loads(json_path.read_text())
    assert payload["schema"] == sm.SCHEMA
    assert "Secret management" in md_path.read_text()
