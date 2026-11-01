"""Tests for the SSRF drill.

Two things have to hold: the platform refuses what it must refuse, and the drill
would notice if it stopped. The second is why the redirect row carries a control
that follows the redirect when no guard is installed — without it, "the redirect
was refused" could mean "urllib never followed it".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _relative in ("scripts", "services/api", "services/database", "shared/shared_models",
                  "shared/shared_config"):
    sys.path.insert(0, str(ROOT / _relative))

import ssrf  # noqa: E402


@pytest.fixture(scope="module")
def report() -> dict:
    return ssrf.measure()


def _row(report: dict, row_id: str) -> dict:
    return next(row for row in report["rows"] if row["id"] == row_id)


def test_schema_and_counts(report: dict) -> None:
    assert report["schema"] == ssrf.SCHEMA
    assert report["counts"]["FAIL"] == 0, [
        row["id"] for row in report["rows"] if row["verdict"] == "FAIL"]
    for row in report["rows"]:
        assert row["probes"], f"{row['id']} has no probe"


def test_target_policy_row_is_the_executed_policy(report: dict) -> None:
    row = _row(report, "target_policy")
    names = {probe["probe"] for probe in row["probes"]}
    assert "scope-rejects-metadata" in names
    assert "scope-rejects-loopback" in names
    assert row["verdict"] == "PASS", [probe for probe in row["probes"] if not probe["ok"]]


def test_guard_refuses_metadata_and_direct_sockets(report: dict) -> None:
    guard_row = _row(report, "runtime_guard")
    assert any("169.254.169.254" in probe["observed"] for probe in guard_row["probes"])
    sockets_row = _row(report, "direct_sockets")
    assert sockets_row["verdict"] == "PASS"


def test_rebinding_is_refused(report: dict) -> None:
    row = _row(report, "dns_rebinding")
    observations = " ".join(probe["observed"] for probe in row["probes"])
    assert "DNS rebinding" in observations
    assert "pinned address" in observations
    assert row["verdict"] == "PASS"


def test_redirect_control_proves_the_follow_happens(report: dict) -> None:
    row = _row(report, "redirects")
    probes = {probe["probe"]: probe for probe in row["probes"]}
    assert probes["control-redirect-is-followed-without-the-guard"]["ok"] is True, (
        "the drill must show urllib follows the redirect when nothing stops it, or "
        "the refusal below proves nothing")
    assert probes["redirect-to-unapproved-host-refused"]["ok"] is True
    assert probes["redirect-to-metadata-address-refused"]["ok"] is True


def test_the_drill_fails_when_the_guard_is_removed(monkeypatch) -> None:
    """Negative control: neutralise the guard and the redirect row must go red."""
    from api.security import egress_guard as guard

    monkeypatch.setattr(guard, "install_egress_guard", lambda allowlist: None)
    monkeypatch.setattr(guard, "uninstall_egress_guard", lambda: None)

    probes = {probe.name: probe for probe in ssrf.probe_redirect()}
    assert probes["control-redirect-is-followed-without-the-guard"].ok is True
    assert probes["redirect-to-unapproved-host-refused"].ok is False, (
        "with the guard neutralised the redirect was still reported as refused — "
        "the check is blind")
    assert probes["redirect-to-metadata-address-refused"].ok is False


def test_controls_show_the_guard_allows_what_it_should(report: dict) -> None:
    row = _row(report, "controls")
    probes = {probe["probe"]: probe for probe in row["probes"]}
    assert probes["allowlisted-destination-still-works"]["ok"] is True
    assert probes["control-without-guard-still-works"]["ok"] is True


def test_cli_writes_reports(tmp_path) -> None:
    json_path, md_path = tmp_path / "ssrf.json", tmp_path / "ssrf.md"
    assert ssrf.main(["--json", str(json_path), "--md", str(md_path)]) == 0
    assert "SSRF" in md_path.read_text()
