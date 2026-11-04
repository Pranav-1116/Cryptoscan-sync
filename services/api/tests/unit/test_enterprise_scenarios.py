"""The simulation boundary must name scenarios this build can actually run.

The failure mode this file exists for is subtle: a boundary table is prose that
nobody executes, so it drifts. Someone removes a scenario from the agility
catalogue and the table keeps advertising it; someone renames a twin scenario
kind and ``covered_by`` points at a string that means nothing. Both produce the
same symptom at a bank — a demo that pauses and then does something else.

So every ``covered_by`` entry is resolved here against the engine it names:

* ``agility`` → ``services/agility/agility/twin_scenarios.py::SCENARIOS``
* ``twin``    → ``shared_models/estate_twin.py::SIMULATION_KINDS``

An entry that does not resolve fails the test. The route is checked too, because
it re-resolves the ids at request time and reports ``unresolved`` rather than
turning a stale row into an ``EXISTS``.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(ROOT / "shared" / "shared_models"))
sys.path.insert(0, str(ROOT / "services" / "api"))
sys.path.insert(0, str(ROOT / "services" / "agility"))

from shared_models import enterprise_scenarios as es  # noqa: E402


def _engines() -> dict[str, set[str]]:
    from agility.twin_scenarios import SCENARIOS as AGILITY_SCENARIOS
    from shared_models.estate_twin import SIMULATION_KINDS

    return {
        es.AGILITY: set(AGILITY_SCENARIOS),
        es.TWIN: set(SIMULATION_KINDS),
    }


def test_the_ten_scenarios_are_the_ten_an_enterprise_engine_is_asked_for():
    """Pinned by id: a scenario cannot quietly leave the boundary table."""
    assert [row["id"] for row in es.SCENARIOS] == [
        "PQC_MIGRATION",
        "TLS_DOWNGRADE",
        "CERTIFICATE_COMPROMISE",
        "HSM_FAILURE",
        "KMS_FAILURE",
        "CRYPTO_LIBRARY_COMPROMISE",
        "SUPPLY_CHAIN_COMPROMISE",
        "TRUST_COMPROMISE",
        "SERVICE_COMPROMISE",
        "CUSTOM_SCENARIO",
    ]


def test_every_advertised_scenario_resolves_in_this_build():
    engines = _engines()
    for row in es.SCENARIOS:
        for entry in row["covered_by"]:
            assert entry["engine"] in engines, f"{row['id']}: unknown engine {entry['engine']}"
            assert entry["scenario"] in engines[entry["engine"]], (
                f"{row['id']} advertises {entry['engine']}/{entry['scenario']}, which this build "
                "does not execute"
            )


def test_only_pqc_migration_is_fully_covered():
    """The one EXISTS row must be the one the engines actually implement."""
    exists = [row for row in es.SCENARIOS if row["status"] == es.EXISTS]
    assert [row["id"] for row in exists] == ["PQC_MIGRATION"]
    covered = {(entry["engine"], entry["scenario"]) for entry in exists[0]["covered_by"]}
    assert covered == {
        ("agility", "pqc_migration"),
        ("twin", "MIGRATE_QUANTUM_VULNERABLE"),
    }


def test_the_generic_engine_is_not_claimed():
    catalogue = es.catalogue()
    assert catalogue["rollup"]["scenarios"] == 10
    # No row is left with no model at all — but nine of ten still model only part of the
    # mechanism, and each says which part it cannot see.
    assert catalogue["rollup"][es.ABSENT] == 0
    assert catalogue["rollup"][es.PARTIAL] == 9
    assert any(
        "generic enterprise simulation engine" in sentence.lower()
        for sentence in catalogue["cannot_claim"]
    )
    # A row that says ABSENT must not borrow an existing scenario to look busy.
    for row in es.SCENARIOS:
        if row["status"] == es.ABSENT:
            assert row["covered_by"] == [], row["id"]


def test_a_partial_or_absent_row_states_what_it_cannot_do():
    for row in es.SCENARIOS:
        if row["status"] in {es.PARTIAL, es.ABSENT}:
            assert row["cannot"], row["id"]


def test_the_route_resolves_the_table_at_request_time():
    from api.routers import estate_graph

    signature = inspect.signature(estate_graph.estate_twin_simulation_scenarios)
    assert "user" in signature.parameters
    assert signature.parameters["user"].default is not inspect.Parameter.empty

    served = estate_graph.estate_twin_simulation_scenarios(user="viewer")
    assert served["schema"] == es.SCHEMA
    # Annotating the response must not leak into the module-level table.
    assert "present" not in es.SCENARIOS[0]["covered_by"][0]
    assert served["unresolved"] == []
    assert served["rollup"] == es.catalogue()["rollup"]
    engines = _engines()
    assert served["executable"] == {engine: sorted(ids) for engine, ids in engines.items()}
    # The ids the engines carry are all visible in the served payload, so a reader
    # can see what an EXISTS row points at without reading the source.
    for row in served["scenarios"]:
        for entry in row["covered_by"]:
            assert entry["present"] is True


def test_the_route_reports_an_unresolved_row_instead_of_hiding_it(monkeypatch):
    """If a row drifts, the route says so — it does not fall back to EXISTS."""
    from api.routers import estate_graph

    drifted = dict(es.SCENARIOS[0])
    drifted["covered_by"] = [{"engine": es.AGILITY, "scenario": "not_a_scenario"}]
    monkeypatch.setattr(es, "SCENARIOS", (drifted,))

    served = estate_graph.estate_twin_simulation_scenarios(user="viewer")
    assert served["unresolved"] == ["PQC_MIGRATION: agility/not_a_scenario"]
    assert served["scenarios"][0]["covered_by"][0]["present"] is False


def test_a_row_that_cannot_name_an_implementer_is_refused():
    with pytest.raises(ValueError):
        es._scenario("X", "X", es.EXISTS)
    with pytest.raises(ValueError):
        es._scenario("X", "X", es.ABSENT)
    with pytest.raises(ValueError):
        es._scenario("X", "X", "PROBABLY")
