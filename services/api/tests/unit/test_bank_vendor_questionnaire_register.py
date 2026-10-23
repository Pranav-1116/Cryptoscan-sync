"""Traceability integrity is deliberately not bank acceptance."""
from copy import deepcopy
import json

import pytest
from bank_vendor_questionnaire import CATALOG, EXPECTED, main, review


@pytest.fixture
def catalog():
    return json.loads(CATALOG.read_text())


def test_all45_original_and12_additional_questions_remain_open(catalog):
    result = review(catalog)
    assert result["register_integrity"] == "PASS"
    assert result["questions_mapped"] == 57
    assert {q["id"] for q in result["open_acceptance"]} == EXPECTED
    assert result["bank_approved"] is False
    assert result["discovery_completeness_proven"] is False
    assert result["source_reference_sha256"]


@pytest.mark.parametrize("change", ["missing", "duplicate", "unknown", "approval", "empty_answer", "no_evidence"])
def test_register_cannot_drop_questions_or_invent_approval(catalog, change):
    if change == "missing": catalog["questions"].pop()
    elif change == "duplicate": catalog["questions"][-1] = deepcopy(catalog["questions"][0])
    elif change == "unknown": catalog["questions"][0]["id"] = "invented"
    elif change == "approval": catalog["questions"][0]["status"] = "QUALIFIED"
    elif change == "empty_answer": catalog["questions"][0]["acceptance_needed"] = " "
    else: catalog["questions"][0]["source_refs"] = []
    with pytest.raises(ValueError): review(catalog)


@pytest.mark.parametrize("path", ["/etc/passwd", "../outside", "missing-source.py"])
def test_source_references_cannot_escape_or_silently_disappear(catalog, path):
    catalog["questions"][0]["source_refs"] = [path]
    with pytest.raises(ValueError): review(catalog)


def test_symlink_evidence_does_not_count_as_source(catalog, tmp_path):
    (tmp_path / "real").write_text("not bank evidence")
    (tmp_path / "alias").symlink_to(tmp_path / "real")
    catalog["questions"][0]["source_refs"] = ["alias"]
    with pytest.raises(ValueError, match="Symlink"): review(catalog, tmp_path)


def test_strict_mode_fails_closed_despite_valid_register(capsys):
    assert main(["--strict"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["register_integrity"] == "PASS"
    assert result["bank_approved"] is False


def test_nonobject_input_is_controlled_failure(tmp_path, capsys):
    path = tmp_path / "invalid.json"; path.write_text("[]")
    assert main(["--catalog", str(path)]) == 2
    assert json.loads(capsys.readouterr().out)["register_integrity"] == "FAIL"
