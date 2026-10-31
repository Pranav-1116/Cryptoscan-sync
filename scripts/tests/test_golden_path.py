"""The golden path must be able to fail, or its PASS is worth nothing.

Two kinds of test here:

* the five families walk the whole chain with the assertions from the harness,
  so a regression in a collector, the ingest, the catalogue, the twin or the BOM
  projection turns this suite red;
* **negative controls** — the same harness is handed a poisoned family and must
  return FAIL, not a pass. A golden path that cannot detect a dropped asset, a
  missing BOM identity or an unreachable console is a report, not a test.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from scripts import golden_path as golden


FAMILY_NAMES = [family.name for family in golden.FAMILIES]
STAGES = ("collect", "api", "evidence", "db", "twin", "bom", "ui")


@pytest.mark.parametrize("name", FAMILY_NAMES)
def test_family_walks_every_hop(name):
    row = golden.run_family(golden.FAMILIES_BY_NAME[name])
    assert row["verdict"] == golden.PASS, json.dumps(row, indent=1)[:4000]
    assert [stage["stage"] for stage in row["stages"]] == list(STAGES)
    assert all(stage["verdict"] == golden.PASS for stage in row["stages"])
    assert row["stages_passed"] == row["stages_total"] == len(STAGES)
    assert row["failed_stages"] == [] and row["skipped_stages"] == []


@pytest.mark.parametrize("name", FAMILY_NAMES)
def test_every_hop_records_what_it_saw(name):
    """A passing hop without observations would be an assertion, not evidence."""
    row = golden.run_family(golden.FAMILIES_BY_NAME[name])
    for stage in row["stages"]:
        assert stage["observations"], f"{stage['stage']} asserted nothing"
        assert stage["detail"]
    counts = row["stages"][0]["observations"]
    assert counts["assets"] and counts["evidence"]


def test_five_families_are_the_five_named_planes():
    assert FAMILY_NAMES == ["runtime", "static", "network_tls", "pki", "cloud"]
    assert {family.plane for family in golden.FAMILIES} == {
        "RUNTIME", "STATIC", "NETWORK", "PKI", "CLOUD"}


def test_measure_reports_completeness_not_just_successes():
    report = golden.measure()
    assert report["schema"] == golden.SCHEMA
    assert report["families"] == report["expected_families"] == 5
    assert report["complete"] is True
    assert report["stages_total"] == 35
    assert report["limits"], "a golden path without stated limits is a claim"


# --------------------------------------------------------------- falsification --- #
def test_a_dropped_asset_fails_the_collect_hop():
    """The harness must notice one fewer asset than the family promised."""
    family = dataclasses.replace(golden.FAMILIES_BY_NAME["runtime"], assets=4)
    row = golden.run_family(family)
    assert row["verdict"] == golden.FAIL
    assert "collect" in row["failed_stages"]
    assert row["stages"][0]["observations"]["assets"] == 3


def test_an_empty_package_skips_downstream_and_is_not_a_pass():
    """SKIPPED must never be read as success: an empty collector fails the family."""
    poison = dataclasses.replace(
        golden.FAMILIES_BY_NAME["static"],
        collect=lambda db: {"assets": [], "evidence": []},
    )
    row = golden.run_family(poison)
    assert row["verdict"] == golden.FAIL
    assert row["failed_stages"] == ["collect"]
    assert row["skipped_stages"] == ["api", "evidence", "db", "twin", "bom", "ui"]
    assert row["stages_passed"] == 0


def test_a_bom_without_the_planted_identity_fails_the_bom_hop():
    """Every other hop can be right and the BOM still lose the component."""
    family = dataclasses.replace(golden.FAMILIES_BY_NAME["static"],
                                bom_match=lambda component: False)
    row = golden.run_family(family)
    assert row["verdict"] == golden.FAIL
    assert row["failed_stages"] == ["bom"]
    bom = next(stage for stage in row["stages"] if stage["stage"] == "bom")
    assert "no component matching the planted identity" in bom["detail"]


def test_a_console_that_never_calls_the_boms_fails_the_ui_hop(tmp_path, monkeypatch):
    """The UI hop reads the checkout, so point it at an empty console."""
    monkeypatch.setattr(golden, "FRONTEND", tmp_path)
    stage = golden.stage_ui(golden.FAMILIES_BY_NAME["runtime"])
    assert stage.verdict == golden.FAIL
    assert "no client function" in stage.detail


def test_ui_hop_names_the_client_function_it_found():
    stage = golden.stage_ui(golden.FAMILIES_BY_NAME["pki"])
    assert stage.verdict == golden.PASS
    catalog = stage.observations["catalog"]
    assert catalog["client_symbols"]
    assert catalog["callers"] and catalog["tests"]
    assert catalog["callers"][0].startswith("frontend/src/")


def test_ui_symbol_lookup_is_not_fooled_by_a_distant_declaration():
    """A symbol hundreds of lines above a path is a different endpoint."""
    symbols = golden._api_symbols("/api/v1/estate/evidence/boms?bom=")
    assert "apiEstateBomComponents" in symbols


# -------------------------------------------------------------- known defects --- #
def test_the_static_family_reports_its_identity_defect():
    """A UUID presented as an application name is a defect, and is reported as one."""
    row = golden.run_family(golden.FAMILIES_BY_NAME["static"])
    assert row["verdict"] == golden.PASS
    defects = [d for d in row["defects"] if d["id"] == "asset-named-by-raw-identifier"]
    assert len(defects) == row["stages"][2]["observations"]["evidence_rows"]
    assert all(d["severity"] == "identity-quality" for d in defects)


# ------------------------------------------------------------------- artefacts --- #
def test_markdown_artifact_states_the_limits():
    path = golden.REPO_ROOT / "docs" / "bank-environment" / "113-golden-path.md"
    if not path.exists():  # pragma: no cover - regenerated by the script
        pytest.skip("artifact not generated in this checkout")
    text = path.read_text(encoding="utf-8")
    assert "What this does not prove" in text
    assert "not render this payload" in text


def test_json_artifact_matches_the_live_run():
    path = golden.REPO_ROOT / "docs" / "bank-environment" / "113-golden-path.json"
    if not path.exists():  # pragma: no cover
        pytest.skip("artifact not generated in this checkout")
    artifact = json.loads(path.read_text(encoding="utf-8"))
    assert artifact["schema"] == golden.SCHEMA
    assert artifact["families"] == len(golden.FAMILIES)
    assert {row["family"] for row in artifact["rows"]} == set(FAMILY_NAMES)
