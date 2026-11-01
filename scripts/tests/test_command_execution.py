"""Tests for the command-execution drill.

The drill's value is that it can fail. So the tests check both directions: the
tree has no shell sink and no unvalidated call site, *and* the instrument that
says so actually reports a violation when one is put in front of it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "services" / "database"))
sys.path.insert(0, str(ROOT / "shared" / "shared_models"))
sys.path.insert(0, str(ROOT / "shared" / "shared_config"))

import command_execution as ce  # noqa: E402


@pytest.fixture(scope="module")
def report() -> dict:
    return ce.measure()


def _row(report: dict, row_id: str) -> dict:
    return next(row for row in report["rows"] if row["id"] == row_id)


def test_schema_and_verdicts(report: dict) -> None:
    assert report["schema"] == ce.SCHEMA
    assert set(report["counts"]) == {"PASS", "PARTIAL", "FAIL"}
    for row in report["rows"]:
        assert row["verdict"] in {"PASS", "PARTIAL", "FAIL"}
        assert row["question"].endswith("?")
        assert row["probes"], f"{row['id']} has no probe — an unprobed row is an assertion"


def test_census_excludes_itself_and_test_files() -> None:
    census = ce.census()
    assert census["exempt"] == sorted(str(path) for path in ce.CENSUS_EXEMPT)
    assert census["exempt"], "the census must say what it excluded"
    assert census["by_style"]["shell"] == 0
    for site in census["sites"]:
        assert "/tests/" not in site.module
        assert not site.module.endswith("command_execution.py")


def test_census_still_sees_call_sites() -> None:
    """A census that finds nothing is broken, not clean."""
    census = ce.census()
    assert len(census["sites"]) > 20, "the census found almost no subprocess call"
    assert census["modules"] > 10


def test_no_shell_sink_in_product_code(report: dict) -> None:
    row = _row(report, "shell_sinks")
    assert row["verdict"] == "PASS", row["sinks"]
    assert row["sinks"] == []
    assert ce.census()["by_style"]["string"] == 0


def test_hidden_sink_is_detected(tmp_path, monkeypatch) -> None:
    """Negative control: a planted `shell=True` must appear as a finding."""
    planted = ROOT / "services" / "database" / "planted_sink_drill.py"
    planted.write_text(
        "import subprocess\n\n\ndef run(text):\n"
        "    subprocess.run(text, shell=True)\n"
    )
    try:
        census = ce.census()
    finally:
        planted.unlink()
    planted_hits = [finding for finding in census["findings"]
                    if "planted_sink_drill.py" in finding]
    assert planted_hits, census["findings"]
    assert census["by_style"]["shell"] > 0, (
        "the planted string was found but not classified as a shell sink")


def test_hostile_inputs_are_refused_by_the_recorder(report: dict) -> None:
    row = _row(report, "argument_injection")
    assert row["verdict"] == "PASS", row["findings"]
    probes = {probe["probe"]: probe for probe in row["probes"]}
    assert probes["hostile-inputs-contained"]["ok"] is True
    assert probes["control-vulnerable-sink"]["ok"] is True, (
        "the deliberately vulnerable control was not reported — the drill is blind")


def test_every_canary_writes_or_executes_nothing() -> None:
    """The canaries must be inert: after a run, none of the files they would create exist."""
    before = sorted(ce.CANARY_DIR.glob("*")) if ce.CANARY_DIR.exists() else []
    ce.measure()
    after = sorted(ce.CANARY_DIR.glob("*")) if ce.CANARY_DIR.exists() else []
    assert after == before, [str(path) for path in after if path not in before]


def test_end_of_options_is_honest(report: dict) -> None:
    row = _row(report, "end_of_options")
    assert row["verdict"] == "PASS", row["probes"]
    probes = {probe["probe"]: probe for probe in row["probes"]}
    assert probes["every-driven-site-classified"]["ok"] is True, (
        "a driven site did not map onto a spawn call: the population is incomplete, "
        "so the pass would overstate")
    assert "call sites take a caller-supplied positional" in probes[
        "untrusted-positional-terminated"]["observed"]


def test_end_of_options_fails_when_a_site_drops_the_terminator(monkeypatch) -> None:
    """Negative control: remove `--` from the module text and the row must fail."""
    original = ce._module_text
    monkeypatch.setattr(ce, "_module_text",
                        lambda row: original(row).replace('"--", reference', "reference"))
    row = _row(ce.measure(), "end_of_options")
    assert row["verdict"] == "FAIL", row["probes"]


def test_privileged_surfaces_measured(report: dict) -> None:
    row = _row(report, "privileged_surfaces")
    observed = row["probes"][0]["observed"]
    for needle in ("docker socket", "pod exec", "setuid"):
        assert needle in observed


def test_cli_writes_reports(tmp_path) -> None:
    json_path = tmp_path / "ce.json"
    md_path = tmp_path / "ce.md"
    assert ce.main(["--json", str(json_path), "--md", str(md_path)]) == 0
    assert json_path.exists() and md_path.exists()
    assert "command execution" in md_path.read_text().lower()
