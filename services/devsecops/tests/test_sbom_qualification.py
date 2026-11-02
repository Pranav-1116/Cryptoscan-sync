"""The parser qualification matrix, executed rather than asserted.

These tests do not restate the matrix — ``qualify()`` writes each fixture to
disk and runs the real ``scan_source`` over it. What they pin down is that the
matrix cannot quietly stop measuring: an empty matrix, a case that produces no
component, or a defect counted as a pass all fail here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from devsecops import sbom_qualification as sq
from devsecops import sbom_scan


@pytest.fixture(scope="module")
def report() -> dict:
    return sq.qualify()


def test_every_case_is_executed(report: dict) -> None:
    assert report["cases"] == len(sq.CASES)
    assert {row["id"] for row in report["rows"]} == {case.id for case in sq.CASES}


def test_no_case_produces_an_empty_sbom(report: dict) -> None:
    for row in report["rows"]:
        assert row["components_found"], row["id"]
        assert row["manifests_seen"], row["id"]


def test_the_matrix_is_green(report: dict) -> None:
    assert report["counts"] == {"PASS": len(sq.CASES), "PARTIAL": 0, "FIX": 0}
    assert report["qualified"] is True


def test_every_reviewed_ecosystem_is_qualified(report: dict) -> None:
    qualified = {row["ecosystem"] for row in report["ecosystems"]}
    assert qualified == set(sq.ECOSYSTEMS)


def test_a_broken_reader_turns_the_matrix_red(tmp_path: Path) -> None:
    """A case whose expectation cannot be met must report FIX, not quietly pass."""
    case = sq.Case(
        id="broken_reader", ecosystem="npm", manifest="package.json", lockfile=None,
        revision="manifest only",
        files={"package.json": '{"dependencies": {"jose": "^5.0.0"}}'},
        expect=(("not-in-this-file", "1.0.0"),),
    )
    row = sq.qualify_case(case, tmp_path)
    assert row["verdict"] == sq.FIX
    assert "missing" in row["reason"]


def test_csproj_is_dispatched_by_suffix(tmp_path: Path) -> None:
    """The parser is registered as ``.csproj``; a file named ``App.csproj`` must reach it."""
    (tmp_path / "App.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<PackageReference Include="BouncyCastle.Cryptography" Version="2.3.1" />'
        "</ItemGroup></Project>",
        encoding="utf-8")
    result = sbom_scan.scan_source(str(tmp_path))
    assert [row["name"] for row in result["packages"]] == ["bouncycastle.cryptography"]
    assert result["manifests"] == ["App.csproj"]


def test_pyproject_alone_is_not_an_empty_sbom(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["cryptography>=42.0.5", "requests[socks]>=2.31 ; '
        "python_version >= '3.9'\"]\n\n"
        '[tool.poetry.group.audit.dependencies]\nbandit = "^1.7.5"\n',
        encoding="utf-8")
    result = sbom_scan.scan_source(str(tmp_path))
    rows = {row["name"]: row for row in result["packages"]}
    assert set(rows) == {"cryptography", "requests", "bandit"}
    assert rows["requests"]["version_constraint"] == "RANGE"
    assert rows["requests"]["raw_spec"] == ">=2.31"
    assert rows["bandit"]["version_constraint"] == "RANGE"


def test_pipfile_declares_and_a_pin_is_exact(tmp_path: Path) -> None:
    (tmp_path / "Pipfile").write_text(
        '[packages]\ncryptography = "==42.0.5"\nrequests = "*"\n', encoding="utf-8")
    rows = {row["name"]: row for row in sbom_scan.scan_source(str(tmp_path))["packages"]}
    assert rows["cryptography"]["version_constraint"] == "EXACT"
    assert rows["cryptography"]["version"] == "42.0.5"
    assert rows["requests"]["version_constraint"] == "ANY"
    assert rows["requests"]["version"] is None


def test_a_declared_specifier_survives_the_lockfile_merge(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\ncryptography = "^42.0.5"\n', encoding="utf-8")
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "cryptography"\nversion = "42.0.5"\n', encoding="utf-8")
    rows = {row["name"]: row for row in sbom_scan.scan_source(str(tmp_path))["packages"]}
    assert rows["cryptography"]["version"] == "42.0.5"
    assert rows["cryptography"]["scope"] == "resolved"
    assert rows["cryptography"]["declared_spec"] == "^42.0.5"


@pytest.mark.parametrize(("spec", "version", "constraint"), [
    ("^5.0.0", "5.0.0", "RANGE"),
    ("5.0.0", "5.0.0", "EXACT"),
    ("*", None, "ANY"),
    ("git+https://example.invalid/pkg.git", None, "NON_VERSION"),
])
def test_specifier_classification(spec: str, version: str | None,
                                  constraint: str) -> None:
    from container_scanner.parsers.package_parsers import classify_spec

    assert classify_spec(spec) == (version, constraint)


def test_the_written_report_is_stable(tmp_path: Path) -> None:
    out = tmp_path / "matrix.json"
    out.write_text(sq.qualify()["statement"], encoding="utf-8")
    assert out.read_text(encoding="utf-8").startswith("15 of 15")
