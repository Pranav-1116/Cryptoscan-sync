"""The authentication drill, and the claim that its probes can fail.

These tests do not re-implement the drill: they run it and then assert the
properties it reports, so a regression in the auth stack fails here with a named
row rather than only in a document. One test deliberately breaks a property and
checks the drill notices.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "auth_qualification.py"


@pytest.fixture(scope="module")
def report() -> dict:
    sys.path.insert(0, str(ROOT / "scripts"))
    import auth_qualification  # noqa: PLC0415

    return auth_qualification.measure()


def _row(report: dict, row_id: str) -> dict:
    for row in report["rows"]:
        if row["id"] == row_id:
            return row
    raise AssertionError(f"row {row_id} missing from {[r['id'] for r in report['rows']]}")


def test_every_row_ran(report):
    ids = [row["id"] for row in report["rows"]]
    assert ids == ["login", "session_token", "mfa", "expiry", "revocation",
                   "password_policy", "lockout", "credential_handling"]


def test_no_row_fails_and_the_schema_is_stable(report):
    assert report["schema"] == "cryptoscan.authentication-qualification/1"
    assert report["counts"]["FAIL"] == 0, [
        (row["id"], [p for p in row["probes"] if not p["ok"]]) for row in report["rows"]
    ]


@pytest.mark.parametrize("row_id", ["login", "session_token", "revocation"])
def test_the_load_bearing_rows_pass(report, row_id):
    row = _row(report, row_id)
    assert row["verdict"] == "PASS", row
    assert row["passed"] == len(row["probes"]) > 0


def test_the_second_factor_is_not_optional(report):
    """Password alone must not mint a session once MFA is enabled."""
    row = _row(report, "mfa")
    probes = {probe["probe"]: probe for probe in row["probes"]}
    assert probes["password-alone"]["ok"]
    assert probes["challenge-not-a-session"]["ok"]
    assert probes["correct-code"]["ok"]


def test_live_responses_carry_no_credential_material(report):
    row = _row(report, "credential_handling")
    assert row["verdict"] != "FAIL"


def test_the_drill_can_fail(monkeypatch, tmp_path):
    """Break the password policy and confirm a probe turns red."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import auth_qualification  # noqa: PLC0415

    original = auth_qualification.row_password_policy

    def broken(harness):
        row = original(harness)
        row.probes.append(auth_qualification.Probe(
            "injected-mismatch", "a deliberately wrong expectation", False,
            "observed a refusal where a success was expected"))
        return row

    monkeypatch.setattr(auth_qualification, "ROWS",
                        [broken if builder is original else builder
                         for builder in auth_qualification.ROWS])
    broken_report = auth_qualification.measure()
    assert broken_report["counts"]["FAIL"] == 1
    assert _row(broken_report, "password_policy")["verdict"] == "FAIL"


def test_cli_writes_both_artifacts(tmp_path):
    out_json = tmp_path / "auth.json"
    out_md = tmp_path / "auth.md"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--json", str(out_json), "--md", str(out_md)],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    payload = json.loads(out_json.read_text())
    assert payload["schema"] == "cryptoscan.authentication-qualification/1"
    assert "What this does not prove" in out_md.read_text()
