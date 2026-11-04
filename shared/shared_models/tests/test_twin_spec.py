"""The Digital Twin specification must be measurable against the tree, not asserted.

``shared_models/twin_spec.py`` claims that eighteen relationship types, eight layers,
thirteen screens and eleven lifecycle steps are built. A claim is only worth anything
if breaking the code breaks the claim — so this test resolves every proof, refuses a
status that is not in the vocabulary, and refuses a gap that is not written down.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from shared_models import estate_graph, estate_twin, twin_spec

ROOT = Path(__file__).resolve().parents[3]
STATUSES = {twin_spec.SUPPORTED, twin_spec.PARTIAL, twin_spec.ABSENT}


def _rows():
    return [*twin_spec.SECTIONS, *twin_spec.LAYERS, *twin_spec.PIPELINE_STEPS]


def _split(proof: str) -> tuple[str, str]:
    """``path`` or ``path:marker`` — a marker is a symbol for ``.py``, text elsewhere."""
    path, _, marker = proof.partition(":")
    return path, marker


class TestTheRegisterIsWellFormed:
    def test_every_status_is_in_the_vocabulary(self):
        for row in _rows():
            assert row["status"] in STATUSES, row["id"]

    def test_a_row_that_is_not_supported_states_its_gap(self):
        for row in _rows():
            if row["status"] == twin_spec.SUPPORTED:
                continue
            assert row["gap"].strip(), f"{row['id']} is {row['status']} with no gap sentence"
            assert len(row["gap"]) > 40, f"{row['id']} has a gap too short to mean anything"

    def test_a_supported_row_still_has_a_proof(self):
        for row in _rows():
            assert row["proof"], f"{row['id']} is asserted without a proof"

    def test_identifiers_are_unique(self):
        ids = [row["id"] for row in _rows()]
        assert len(ids) == len(set(ids))


class TestEveryProofResolves:
    def test_every_python_proof_names_a_symbol_that_exists(self):
        for row in _rows():
            for proof in row["proof"]:
                path, marker = _split(proof)
                if not path.endswith(".py") or not marker:
                    continue
                assert (ROOT / path).exists(), f"{row['id']}: {path} does not exist"
                # `shared/<root>/<pkg>/m.py` and `services/<root>/<pkg>/m.py` both put
                # the first two segments on PYTHONPATH, so the module starts at the third
                parts = Path(path).with_suffix("").parts
                module_name = ".".join(parts[2:])
                module = importlib.import_module(module_name)
                assert hasattr(module, marker), f"{row['id']}: {module_name}.{marker} is gone"

    def test_every_file_proof_exists(self):
        for row in _rows():
            for proof in row["proof"]:
                path, _ = _split(proof)
                if path.startswith("/"):
                    continue
                assert (ROOT / path).exists(), f"{row['id']}: {path} does not exist"

    def test_a_document_proof_names_text_the_document_contains(self):
        for row in _rows():
            for proof in row["proof"]:
                path, marker = _split(proof)
                if not path.endswith(".md") or not marker:
                    continue
                body = (ROOT / path).read_text(encoding="utf-8")
                assert marker.lower() in body.lower(), f"{row['id']}: {path} no longer says {marker!r}"


class TestTheRelationshipVocabularyHasNoOrphans:
    def test_the_specification_vocabulary_is_fully_mapped(self):
        assert len(twin_spec.RELATIONSHIP_MAP) == 18
        unmapped = [name for name, pred in twin_spec.RELATIONSHIP_MAP.items() if not pred]
        assert unmapped == []

    def test_every_mapped_predicate_is_a_real_predicate(self):
        for spec_name, predicate in twin_spec.RELATIONSHIP_MAP.items():
            assert predicate in estate_graph.RELATIONSHIP_PREDICATES, spec_name

    def test_the_build_is_not_smaller_than_the_specification(self):
        assert len(estate_graph.RELATIONSHIP_PREDICATES) >= len(twin_spec.RELATIONSHIP_MAP)


class TestTheScreensAreReal:
    def test_every_screen_names_a_component_that_exists(self):
        for screen in twin_spec.SCREENS:
            assert (ROOT / screen["component"]).exists(), screen["id"]

    def test_every_screen_names_a_route(self):
        for screen in twin_spec.SCREENS:
            assert screen["route"].startswith("/"), screen["id"]

    def test_the_thirteen_screens_are_thirteen(self):
        assert len(twin_spec.SCREENS) == 13
        assert len({s["route"] for s in twin_spec.SCREENS}) == 13


class TestTheConformanceDocument:
    def test_counts_match_the_rows(self):
        document = twin_spec.conformance()
        coverage = document["coverage"]
        assert coverage["sections"]["SUPPORTED"] + coverage["sections"]["PARTIAL"] + \
            coverage["sections"]["ABSENT"] == len(document["sections"]) + len(document["layers"])
        assert coverage["screens"] == len(document["screens"]) == 13
        assert coverage["pipeline_steps"] == len(document["pipeline"]) == 11

    def test_relationship_coverage_reports_the_build(self):
        coverage = twin_spec.conformance()["coverage"]
        assert coverage["relationship_types_mapped"] == 18
        assert coverage["mapped_predicates_missing_from_build"] == []
        assert coverage["predicates_in_build"] == len(estate_graph.RELATIONSHIP_PREDICATES)

    def test_the_gap_list_is_exactly_the_rows_that_are_not_supported(self):
        document = twin_spec.conformance()
        expected = {
            row["id"] for row in (*document["sections"], *document["layers"])
            if row["status"] != twin_spec.SUPPORTED
        }
        assert {gap["id"] for gap in document["gaps"]} == expected

    def test_it_is_deterministic(self):
        assert twin_spec.conformance() == twin_spec.conformance()

    def test_it_reports_the_simulation_engine_it_can_see(self):
        document = twin_spec.conformance()
        assert document["coverage"]["simulation_kinds"] == len(estate_twin.SIMULATION_KINDS)


class TestTheLifecycleStatementIsHonest:
    def test_unknown_is_not_removal(self):
        assert "not proof of removal" in twin_spec.LIFECYCLE_STATES["UNKNOWN"].lower()

    def test_every_state_the_dependency_ledger_uses_is_documented(self):
        from cbom.cbom_dependency import LIFECYCLE_STATES as EDGE_STATES

        for state in EDGE_STATES:
            assert state in twin_spec.LIFECYCLE_STATES, state


@pytest.mark.parametrize("layer_id", [row["id"] for row in twin_spec.LAYERS])
def test_each_layer_has_a_verdict(layer_id):
    row = next(layer for layer in twin_spec.LAYERS if layer["id"] == layer_id)
    assert row["status"] in STATUSES
    assert row.get("note") or row.get("gap")
