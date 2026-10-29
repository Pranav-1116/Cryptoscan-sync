"""The Digital Twin chain, link by link (spec 94).

The chain is only useful if it is honest about where it stops. These tests pin
the three refusals the module makes:

* a store that was not read is ``NOT_EVALUATED``, never ``EMPTY``;
* a store that was read and holds nothing is ``EMPTY``, and says why;
* impact and simulation are ``AWAITING_INPUT`` on an estate that has assets —
  computable is not the same as computed.

Plus the ordering, which is a dependency claim: every stage names the endpoint
that serves its full view, and ``first_incomplete_stage`` is the first link that
is neither populated nor merely waiting for input.
"""

from __future__ import annotations

import pytest

from shared_models.estate_graph import EstateGraph, make_evidence

from api import estate_twin_chain as chain_module
from api.estate_twin_chain import (
    AWAITING_INPUT,
    CHAIN_SCHEMA,
    EMPTY,
    NOT_EVALUATED,
    POPULATED,
    STAGES,
    chain,
)


def _graph(*, with_crypto: bool = True) -> EstateGraph:
    """Two assets, one evidenced edge, and — optionally — a crypto fact.

    ``with_crypto=False`` keeps the evidence and the edge but drops the algorithm:
    that is an estate the twin can describe structurally and say nothing about
    cryptographically, which is a different state from an undescribed estate.
    """
    graph = EstateGraph(estate="payments-bank")
    api = graph.add_asset("APPLICATION", "Payment API")
    lb = graph.add_asset("LOAD_BALANCER", "ext-lb-01")
    facts = (
        {"algorithm": "AES", "key_size": 256, "role": "bulk-encryption"}
        if with_crypto
        else {"environment": "production"}
    )
    evidence = graph.add_evidence(
        make_evidence(
            source="runtime-trace",
            evidence_type="RUNTIME_OBSERVED",
            target=api,
            layer="APPLICATION",
            facts=facts,
        )
    )
    graph.assert_relationship(api, "uses", lb, basis="APPROVED_MAPPING", evidence_ids=[evidence])
    return graph


def _bare() -> EstateGraph:
    """Assets with no evidence and no resolvable edge — the twin's thinnest state."""
    graph = EstateGraph(estate="payments-bank")
    graph.add_asset("APPLICATION", "Payment API")
    graph.add_asset("LOAD_BALANCER", "ext-lb-01")
    return graph


def _stages(doc: dict) -> dict[str, dict]:
    return {stage["stage"]: stage for stage in doc["stages"]}


def test_chain_is_the_declared_dependency_order():
    doc = chain(_graph(), history=None, simulations=None)
    assert doc["schema"] == CHAIN_SCHEMA
    assert doc["order"] == [stage[0] for stage in STAGES]
    assert doc["order"] == [
        "ESTATE",
        "ASSETS",
        "RELATIONSHIPS",
        "CRYPTO_GRAPH",
        "EVIDENCE_GRAPH",
        "HISTORY",
        "IMPACT",
        "SIMULATION",
    ]
    # every link says which endpoint serves its full view, and what it answers
    for stage in doc["stages"]:
        assert stage["endpoint"].startswith("/api/v1/estate/evidence/")
        assert stage["question"].endswith("?")
        assert stage["status_meaning"]


def test_unread_stores_are_not_evaluated_not_empty():
    doc = chain(_graph(), history=None, simulations=None)
    stages = _stages(doc)
    for name in ("HISTORY", "SIMULATION"):
        assert stages[name]["status"] == NOT_EVALUATED
        assert stages[name]["reason"]
        assert stages[name]["detail"] in ({}, stages[name]["detail"])
    # the module never invents a zero for a store it did not read
    assert "observations" not in stages["HISTORY"]["detail"]
    assert "stored" not in stages["SIMULATION"]["detail"]


def test_unread_store_carries_the_read_failure_reason():
    doc = chain(
        _graph(),
        history=None,
        history_error="observation store unreadable: disk I/O error",
        simulations=None,
        simulations_error="simulation store unreadable: locked",
    )
    stages = _stages(doc)
    assert "disk I/O error" in stages["HISTORY"]["reason"]
    assert "locked" in stages["SIMULATION"]["reason"]
    assert stages["HISTORY"]["status"] == NOT_EVALUATED


def test_read_but_empty_history_is_empty_with_a_reason():
    empty_summary = {
        "observations": {"total": 0, "current": 0, "historical": 0, "assets": 0, "disputed_facts": 0}
    }
    doc = chain(_graph(), history=empty_summary, simulations=[])
    stages = _stages(doc)
    assert stages["HISTORY"]["status"] == EMPTY
    assert "history starts at the next run" in stages["HISTORY"]["reason"]
    assert stages["HISTORY"]["detail"]["observations"] == 0


def test_populated_history_reports_the_counts_it_was_given():
    summary = {
        "observations": {
            "total": 42,
            "current": 30,
            "historical": 12,
            "assets": 9,
            "disputed_facts": 2,
        }
    }
    stages = _stages(chain(_graph(), history=summary, simulations=[{}, {}]))
    assert stages["HISTORY"]["status"] == POPULATED
    assert stages["HISTORY"]["detail"]["historical"] == 12
    assert stages["HISTORY"]["detail"]["disputed_facts"] == 2
    assert stages["HISTORY"]["reason"] is None
    assert stages["SIMULATION"]["detail"]["stored"] == 2


def test_impact_and_simulation_await_input_on_a_live_estate():
    stages = _stages(chain(_graph(), history=None, simulations=[]))
    assert stages["IMPACT"]["status"] == AWAITING_INPUT
    assert stages["SIMULATION"]["status"] == AWAITING_INPUT
    assert stages["IMPACT"]["detail"]["reachable_assets"] == 2
    # "computable" is stated, but nothing is claimed to have been computed
    assert stages["IMPACT"]["detail"].get("computed") is None


def test_assets_relationships_and_evidence_are_measured_from_the_graph():
    stages = _stages(chain(_graph(), history=None, simulations=None))
    assert stages["ASSETS"]["detail"]["assets"] == 2
    assert stages["ASSETS"]["detail"]["by_type"]["APPLICATION"] == 1
    assert stages["RELATIONSHIPS"]["detail"]["relationships"] == 1
    # keyed on the field the graph actually stores (`predicate`), not an imagined one
    assert stages["RELATIONSHIPS"]["detail"]["by_predicate"] == {"uses": 1}
    assert stages["EVIDENCE_GRAPH"]["detail"]["evidence_records"] == 1
    assert stages["EVIDENCE_GRAPH"]["detail"]["assets_backed"] == 1
    assert stages["EVIDENCE_GRAPH"]["detail"]["assets_unbacked"] == 1


def test_an_estate_with_assets_but_no_crypto_says_so():
    stages = _stages(chain(_graph(with_crypto=False), history=None, simulations=None))
    # structurally described, cryptographically silent — and both are stated
    assert stages["EVIDENCE_GRAPH"]["status"] == POPULATED
    assert stages["CRYPTO_GRAPH"]["status"] == EMPTY
    assert "no algorithm is attached" in stages["CRYPTO_GRAPH"]["reason"]
    # assets alone keep impact computable
    assert stages["IMPACT"]["status"] == AWAITING_INPUT


def test_an_estate_with_no_evidence_says_every_asset_is_unsourced():
    doc = chain(_bare(), history=None, simulations=None)
    stages = _stages(doc)
    assert stages["ASSETS"]["status"] == POPULATED
    assert stages["RELATIONSHIPS"]["status"] == EMPTY
    assert "cannot yet say how they reach each other" in stages["RELATIONSHIPS"]["reason"]
    assert stages["EVIDENCE_GRAPH"]["status"] == EMPTY
    assert "without a source" in stages["EVIDENCE_GRAPH"]["reason"]
    assert doc["first_incomplete_stage"] == "RELATIONSHIPS"


def test_first_incomplete_stage_names_where_the_chain_stops():
    doc = chain(_graph(with_crypto=False), history=None, simulations=None)
    assert _stages(doc)["CRYPTO_GRAPH"]["status"] == EMPTY
    assert doc["first_incomplete_stage"] == "CRYPTO_GRAPH"


def test_a_fully_populated_chain_has_no_incomplete_stage():
    doc = chain(
        _graph(),
        history={"observations": {"total": 3, "current": 3, "historical": 0, "assets": 2, "disputed_facts": 0}},
        simulations=[{}],
    )
    assert doc["first_incomplete_stage"] is None


def test_claim_never_becomes_a_posture_or_coverage_score():
    doc = chain(_graph(), history=None, simulations=None)
    claim = doc["claim"].lower()
    assert "not a crypto posture score" in claim
    assert "coverage percentage" in claim
    assert "%" not in "".join(
        str(stage["detail"])
        for stage in doc["stages"]
        if stage["stage"] in {"ESTATE", "ASSETS", "RELATIONSHIPS"}
    )


def test_unknown_stage_or_status_is_refused_at_the_boundary():
    with pytest.raises(ValueError, match="unknown chain stage"):
        chain_module._stage("NOPE", POPULATED)
    with pytest.raises(ValueError, match="unknown chain status"):
        chain_module._stage("ASSETS", "PROBABLY")


# --------------------------------------------------------------------------- #
# HTTP surface: the chain is wired, guarded, and refuses without a snapshot
# --------------------------------------------------------------------------- #
CHAIN_PATH = "/api/v1/estate/evidence/twin/chain"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/chain.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


def _headers(client):
    token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_chain_endpoint_requires_auth(client):
    assert client.get(CHAIN_PATH).status_code == 401


def test_chain_endpoint_refuses_without_a_stored_snapshot(client):
    """No discovery run is a refusal, not eight empty stages.

    An empty chain would read as "the twin looked and the estate is empty", which
    is exactly the misreading this endpoint exists to prevent.
    """
    response = client.get(CHAIN_PATH, headers=_headers(client))
    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["error"] == "no_estate_discovery"
