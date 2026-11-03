"""Every scenario this build says it has must actually exist in an engine.

``shared_models/enterprise_scenarios.py`` classifies the ten scenarios an
enterprise simulation engine is asked for as EXISTS / PARTIAL / ABSENT. That
classification is only worth anything if the ids in ``covered_by`` resolve to
something executable — otherwise a row drifts into advertising a scenario nobody
wrote, which is the exact overclaim the module exists to prevent.

These tests therefore import the two engines and resolve every id:

* ``agility`` — ``services/agility/agility/twin_scenarios.py::SCENARIOS``
* ``twin``    — ``shared_models/estate_twin.py::SIMULATION_KINDS``

They also pin the arithmetic the platform manifest publishes (``1 of 10
compute today; 7 partial; 2 absent``) so the headline cannot quietly become a
different number.
"""

from __future__ import annotations

import sys
from pathlib import Path

from shared_models import enterprise_scenarios as es

REPO_ROOT = Path(__file__).resolve().parents[3]
AGILITY = REPO_ROOT / "services" / "agility"
if str(AGILITY) not in sys.path:
    sys.path.insert(0, str(AGILITY))


def _agility_scenarios() -> dict:
    from agility import twin_scenarios

    return twin_scenarios.SCENARIOS


def _twin_kinds() -> tuple[str, ...]:
    from shared_models import estate_twin

    return estate_twin.SIMULATION_KINDS


def _engine_ids() -> dict[str, set[str]]:
    return {es.AGILITY: set(_agility_scenarios()), es.TWIN: set(_twin_kinds())}


class TestTheCatalogue:
    def test_ten_scenarios_are_classified(self):
        assert len(es.SCENARIOS) == 10
        ids = [row["id"] for row in es.SCENARIOS]
        assert len(ids) == len(set(ids))

    def test_every_row_has_a_status_from_the_vocabulary(self):
        for row in es.SCENARIOS:
            assert row["status"] in {es.EXISTS, es.PARTIAL, es.ABSENT}
            assert row["status_meaning"] == es.STATUS_MEANING[row["status"]]

    def test_absent_rows_name_no_engine(self):
        """Seeding an existing scenario to look like an absent one is the defect."""
        for row in es.SCENARIOS:
            if row["status"] == es.ABSENT:
                assert row["covered_by"] == [], row["id"]

    def test_non_absent_rows_name_at_least_one_engine(self):
        for row in es.SCENARIOS:
            if row["status"] != es.ABSENT:
                assert row["covered_by"], row["id"]

    def test_every_row_says_what_it_cannot_do(self):
        for row in es.SCENARIOS:
            assert row["cannot"], row["id"]
            for sentence in row["cannot"]:
                assert len(sentence) > 20, (row["id"], sentence)


class TestTheIdsResolve:
    def test_every_covered_by_id_exists_in_its_engine(self):
        known = _engine_ids()
        for row in es.SCENARIOS:
            for ref in row["covered_by"]:
                assert ref["engine"] in known, (row["id"], ref)
                assert ref["scenario"] in known[ref["engine"]], (
                    f"{row['id']} claims {ref['engine']}/{ref['scenario']}, which no engine defines"
                )

    def test_exists_rows_are_executable_end_to_end(self):
        """An EXISTS row must be dispatchable, not merely named."""
        from agility import twin_scenarios

        for row in es.SCENARIOS:
            if row["status"] != es.EXISTS:
                continue
            for ref in row["covered_by"]:
                if ref["engine"] == es.AGILITY:
                    assert ref["scenario"] in twin_scenarios.SCENARIOS
                    assert callable(twin_scenarios.SCENARIOS[ref["scenario"]]["run"])

    def test_the_twin_ids_are_dispatchable(self):
        """A twin id is only real if the engine routes it to a simulation or a cascade."""
        from shared_models import estate_twin

        for row in es.SCENARIOS:
            for ref in row["covered_by"]:
                if ref["engine"] != es.TWIN:
                    continue
                assert ref["scenario"] in estate_twin.SIMULATION_KINDS, ref
                if ref["scenario"] in estate_twin.CASCADE_KINDS:
                    assert callable(estate_twin.cascade)
                    assert callable(estate_twin.cascade_preview)
                    assert ref["scenario"] in estate_twin.CASCADE_RULES
                else:
                    assert callable(estate_twin.simulate)
                    assert callable(estate_twin.preview)
                    assert ref["scenario"] in estate_twin.SCENARIO_INPUTS

    def test_status_is_not_driven_by_the_number_of_engine_ids(self):
        """A row with two ids is not thereby EXISTS — the depth is what decides."""
        counts = {row["id"]: len(row["covered_by"]) for row in es.SCENARIOS}
        absent = [i for i, c in counts.items() if c == 0]
        assert sorted(absent) == ["CUSTOM_SCENARIO", "TRUST_COMPROMISE"]
        assert counts["PQC_MIGRATION"] == 2
        assert next(r for r in es.SCENARIOS if r["id"] == "PQC_MIGRATION")["status"] == es.EXISTS


class TestThePublishedRatio:
    def test_summary_counts_match_the_rows(self):
        summary = es.summary()
        assert summary["scenarios"] == len(es.SCENARIOS) == 10
        assert summary["computing"] == 1
        assert summary["partial"] == 7
        assert summary["absent"] == 2
        assert summary["computing"] + summary["partial"] + summary["absent"] == 10

    def test_summary_headline_refuses_the_generic_engine(self):
        headline = es.summary()["headline"]
        assert "not a generic enterprise simulation engine" in headline
        assert "10" in headline and "1" in headline

    def test_summary_points_at_the_route_that_proves_it(self):
        assert es.summary()["detail_at"] == "/estate/evidence/twin/simulation-scenarios"

    def test_the_platform_manifest_publishes_the_same_numbers(self):
        from shared_models.platform_scope import scope_manifest

        assert scope_manifest()["simulation_coverage"] == es.summary()


class TestTheServedCatalogue:
    def test_the_catalogue_payload_carries_the_boundary_note(self):
        catalogue = es.catalogue()
        assert catalogue["schema"] == es.SCHEMA
        assert len(catalogue["scenarios"]) == 10
        assert "not failures" in catalogue["note"]
        assert "generic enterprise simulation engine" in catalogue["cannot_claim"][0]
        assert catalogue["rollup"] == {
            "scenarios": 10,
            es.EXISTS: 1,
            es.PARTIAL: 7,
            es.ABSENT: 2,
        }

    def test_the_catalogue_is_a_copy(self):
        """A caller annotating a row (the route marks ``present``) must not rewrite the table."""
        first = es.catalogue()
        first["scenarios"][0]["status"] = "ABSENT"
        first["scenarios"][0]["covered_by"].clear()
        assert es.SCENARIOS[0]["status"] == es.EXISTS
        assert es.SCENARIOS[0]["covered_by"]
