"""Conflicts, kept as conflicts (spec 94 §23).

The interesting property of a conflict is what it is *not*: it is not a question the
twin answers. Two observations disagree, both are recorded, and a human decides. These
tests hold the module to that, and to the distinction that makes the list usable:

* **REAL** — two sources on the **same plane** disagree. One is wrong.
* **EXPLAINED** — the values come from different planes and can both be true (a library
  that supports AES-128, an API observed using AES-256-GCM). Calling that a conflict
  teaches an operator to ignore conflicts, which is worse than hiding them.
* **UNKNOWN** — no plane recorded, so it cannot be classified and is treated as real.

Also covered: a dispute seen from both the live observation and the durable fact history
is merged rather than double-counted, an empty answer says it is not a statement that the
bank's sources agree, and nothing in the module edits or resolves anything.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import estate_conflicts as conflicts
from api import estate_observations as history
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"
CONFLICT_URL = f"{BASE}/twin/conflicts"


@pytest.fixture()
def db():
    from db.models.base import Base

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def _payload(
    *,
    algorithms: tuple[str, ...] = ("OpenSSL 3.0.13", "OpenSSL 3.0.13"),
    layers: tuple[str, ...] = ("PLATFORM", "PLATFORM"),
    types: tuple[str, ...] = ("STATIC_OBSERVED", "CONFIGURED"),
    field: str = "engine",
) -> dict:
    """One asset, two observations of one field — the second may disagree with the first."""
    evidence = []
    for index, (value, layer, kind) in enumerate(zip(algorithms, layers, types), start=1):
        evidence.append({
            "evidence_id": f"ev-{index}",
            "source": f"source-{index}",
            "collector": f"collector-{index}",
            "evidence_type": kind,
            "target": "api",
            "layer": layer,
            "facts": {field: value},
        })
    return {
        "estate": "Synthetic Bank",
        "assets": [{"ref": "api", "type": "APPLICATION", "name": "Payment API",
                    "environment": "production"}],
        "evidence": evidence,
    }


def _algorithm_payload(*, layers: tuple[str, str] = ("PLATFORM", "APPLICATION"),
                       types: tuple[str, str] = ("STATIC_OBSERVED", "RUNTIME_OBSERVED")) -> dict:
    """A capability claim and a runtime observation of two different algorithms."""
    return _payload(
        algorithms=("AES-128", "AES-256-GCM"),
        layers=layers,
        types=types,
        field="algorithm",
    )


def test_two_sources_on_one_plane_are_a_real_conflict():
    graph = build_graph(_payload(algorithms=("OpenSSL 3.0.13", "OpenSSL 3.0.11")))

    entries = conflicts.from_graph(graph)

    assert len(entries) == 1
    entry = entries[0]
    assert entry["classification"] == "REAL"
    assert entry["status"] == "CONFLICT"
    assert "same plane" in entry["reason"]
    assert {item["value"] for item in entry["values"]} == {"OpenSSL 3.0.13", "OpenSSL 3.0.11"}
    assert all(item["evidence_id"] for item in entry["values"])


def test_the_same_value_from_two_sources_is_not_a_conflict():
    graph = build_graph(_payload())

    assert conflicts.from_graph(graph) == []


def test_values_from_different_planes_are_explained_rather_than_raised():
    graph = build_graph(_payload(
        algorithms=("AES-128", "AES-256-GCM"),
        layers=("PLATFORM", "APPLICATION"),
        types=("STATIC_OBSERVED", "RUNTIME_OBSERVED"),
    ))

    entry = conflicts.from_graph(graph)[0]

    assert entry["classification"] == "EXPLAINED"
    assert "different planes" in entry["reason"]
    assert "can both be true" in entry["reason"]
    assert "nothing needs fixing" in entry["next_action"]


def test_without_a_recorded_plane_a_disagreement_is_treated_as_real():
    payload = _payload(algorithms=("1.0", "2.0"), types=("CONFIGURED", "CONFIGURED"))
    for item in payload["evidence"]:
        item["layer"] = "UNKNOWN"

    entry = conflicts.from_graph(build_graph(payload))[0]

    assert entry["classification"] == "UNKNOWN"
    assert "cannot be classified" in entry["next_action"]


def test_usage_states_are_not_treated_as_a_disagreement_about_a_fact(db):
    """Two artefacts of one asset with different usage states is normal, not a conflict."""
    graph = build_graph(_algorithm_payload())
    history.sync(db, graph, tenant_id=None)

    fields = {entry["field"] for entry in conflicts.from_history(db, tenant_id=None)}

    assert fields == {"algorithm"}, "only conflict-bearing fields belong in a conflict list"


def test_a_capability_and_a_use_of_different_algorithms_is_a_dispute_the_record_holds(db):
    """The library supports AES-128, the API was observed using AES-256-GCM: both true."""
    graph = build_graph(_algorithm_payload())
    history.sync(db, graph, tenant_id=None)

    entries = conflicts.from_history(db, tenant_id=None)

    dispute = next(entry for entry in entries if entry["field"] == "algorithm")
    assert dispute["status"] == "CONFLICT"
    assert dispute["fact_type"] == "crypto:algorithm"
    assert {item["value"] for item in dispute["values"]} == {"AES-128", "AES-256-GCM"}
    # the recorded fact cites the evidence behind its ASSET, not per value, so the history
    # alone cannot say which plane each value came from — it says so instead of guessing
    assert dispute["classification"] == "UNKNOWN"
    assert dispute["values"][0]["layer"] is None
    assert dispute["values"][0]["evidence_scope"] == "ASSET"


def test_the_two_sources_of_a_conflict_are_merged_not_double_counted(db):
    graph = build_graph(_algorithm_payload())
    history.sync(db, graph, tenant_id=None)

    survey = conflicts.survey(db, graph, tenant_id=None)

    assert survey["count"] == 1, "the same disagreement from two records is one problem"
    entry = survey["conflicts"][0]
    assert entry["seen_by"] == ["history", "observation"]
    assert entry["field"] == "algorithm"
    assert entry["classification"] == "EXPLAINED"
    assert survey["by_classification"]["EXPLAINED"] == 1


def test_a_real_conflict_on_the_same_plane_survives_merging(db):
    graph = build_graph(_algorithm_payload(layers=("PLATFORM", "PLATFORM"),
                                          types=("STATIC_OBSERVED", "CONFIGURED")))
    history.sync(db, graph, tenant_id=None)

    survey = conflicts.survey(db, graph, tenant_id=None)

    assert survey["count"] == 1
    assert survey["real_count"] == 1
    assert survey["conflicts"][0]["next_action"].startswith("two sources on the same plane")


def test_a_real_conflict_is_listed_before_an_explained_one(db):
    real = build_graph(_algorithm_payload(layers=("PLATFORM", "PLATFORM"),
                                          types=("STATIC_OBSERVED", "CONFIGURED")))
    explained = build_graph(_algorithm_payload())

    real_survey = conflicts.survey(db, real, tenant_id=None)
    explained_survey = conflicts.survey(db, explained, tenant_id=None)

    assert real_survey["real_count"] == 1 and real_survey["explained_count"] == 0
    assert explained_survey["explained_count"] == 1 and explained_survey["real_count"] == 0
    assert real_survey["conflicts"][0]["classification"] == "REAL"


def test_nothing_here_resolves_a_conflict(db):
    """The module must not expose a way to choose a winner."""
    exported = set(dir(conflicts))

    assert not {"resolve", "merge", "choose", "winner"} & exported
    payload = _payload(algorithms=("1.0", "2.0"), layers=("PLATFORM", "PLATFORM"))
    graph = build_graph(payload)
    before = {asset["asset_id"]: asset for asset in graph.assets()}
    conflicts.survey(db, graph, tenant_id=None)
    after = {asset["asset_id"]: asset for asset in graph.assets()}

    assert before == after, "reporting a conflict must not change the twin"


def test_an_empty_answer_is_not_a_clean_bill_of_health(db):
    survey = conflicts.survey(db, None, tenant_id=None)

    assert survey["count"] == 0
    assert any("not 'no conflicts in the bank'" in limit for limit in survey["limits"])


# -- API surface ------------------------------------------------------------ #


def test_conflict_endpoint_answers_from_history_without_a_stored_run(api, db):
    client, session = api
    history.sync(session, build_graph(_algorithm_payload()), tenant_id=None)

    response = client.get(CONFLICT_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "cryptoscan.estate-conflicts/1"
    assert body["count"] >= 1
    assert body["conflicts"][0]["status"] == "CONFLICT"
    assert body["limits"]
