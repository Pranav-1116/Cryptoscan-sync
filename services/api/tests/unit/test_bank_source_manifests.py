"""The bank's dependency layer needs real manifests, not a description of them.

``public/source/<bank>/manifests.jsonl`` says what each application declares. It
is data *about* manifests, so the scanner parses none of it: a scan of the bank's
source tree reports ``direct_package_dependencies: 0`` — not because the bank has
no dependencies, but because the tree holds no manifest.

``tools.banking_sandbox.source_manifests`` writes those manifests in each
ecosystem's real format. These tests hold it to that: the files must parse with
the real parser, and a language with no ecosystem must be reported as skipped
rather than invented.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools"))


@pytest.fixture()
def estate(tmp_path: Path) -> Path:
    public = tmp_path / "public"
    (public / "source" / "bank-0001").mkdir(parents=True)
    (public / "applications").mkdir(parents=True)
    (public / "banks").mkdir(parents=True)

    applications = [
        {"app_id": "bank-0001-app-py", "bank_id": "bank-0001", "language": "Python"},
        {"app_id": "bank-0001-app-js", "bank_id": "bank-0001", "language": "JavaScript"},
        {"app_id": "bank-0001-app-java", "bank_id": "bank-0001", "language": "Java"},
        {"app_id": "bank-0001-app-cpp", "bank_id": "bank-0001", "language": "C++"},
        {"app_id": "bank-0001-app-bare", "bank_id": "bank-0001", "language": "Go"},
    ]
    (public / "applications" / "bank-0001.jsonl").write_text(
        "\n".join(json.dumps(row) for row in applications) + "\n", encoding="utf-8"
    )

    declared = [
        {"app_id": "bank-0001-app-py",
         "manifest": {"dependencies": {"OpenSSL": "3.0.13", "SYNTHETIC-helper": "1.0-LAB"}}},
        {"app_id": "bank-0001-app-js",
         "manifest": {"dependencies": {"OpenSSL": "3.0.13"}}},
        {"app_id": "bank-0001-app-java",
         "manifest": {"dependencies": {"SYNTHETIC-vendor-sdk": None}}},
        {"app_id": "bank-0001-app-bare", "manifest": {"dependencies": {}}},
    ]
    (public / "source" / "bank-0001" / "manifests.jsonl").write_text(
        "\n".join(json.dumps(row) for row in declared) + "\n", encoding="utf-8"
    )
    return tmp_path


def test_only_ecosystems_the_lab_can_write_get_a_manifest(estate: Path, tmp_path: Path):
    from banking_sandbox import source_manifests

    out = tmp_path / "manifests"
    summary = source_manifests.build(estate, out)

    assert summary["establishes"] == "DECLARED_DEPENDENCY"
    assert summary["counts"]["manifests"] == 3
    assert (out / "bank-0001" / "bank-0001-app-py" / "requirements.txt").is_file()
    assert (out / "bank-0001" / "bank-0001-app-js" / "package.json").is_file()
    assert (out / "bank-0001" / "bank-0001-app-java" / "pom.xml").is_file()

    skipped = {row["app_id"]: row["reason"] for row in summary["skipped"]}
    # a C++ app has no manifest this lab emits — said out loud, not faked
    assert "no manifest format" in skipped["bank-0001-app-cpp"]
    # an app that declares nothing gets no file rather than an empty one
    assert "no dependencies" in skipped["bank-0001-app-bare"]


def test_the_real_parser_reads_what_was_written(estate: Path, tmp_path: Path):
    from banking_sandbox import source_manifests
    from scanner.analysis.dependency_inventory import collect_package_dependencies, dependency_metadata_files

    out = tmp_path / "manifests"
    source_manifests.build(estate, out)

    files = dependency_metadata_files(out)
    rows, unresolved = collect_package_dependencies(files, out)

    assert unresolved == []
    assert rows, "the parser found no package rows in manifests it should parse"
    ecosystems = {row["ecosystem"] for row in rows}
    assert {"pypi", "npm"} <= ecosystems, ecosystems
    assert {row["name"].lower() for row in rows} >= {"openssl"}
    assert all(row["direct"] is True for row in rows)
    assert all(row["source"] for row in rows)


def test_every_written_manifest_carries_the_synthetic_marker(estate: Path, tmp_path: Path):
    from banking_sandbox import source_manifests

    out = tmp_path / "manifests"
    source_manifests.build(estate, out)
    for path in out.rglob("*"):
        if path.is_file():
            assert source_manifests.SYNTHETIC_MARKER in path.read_text(encoding="utf-8"), path
