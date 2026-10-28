"""REMEDIATE: the twin opens work, and only an observation closes it (spec 94 §23).

The phase was ``NOT_CONNECTED`` for a real reason: the twin could show a conflict, a
coverage loss and a simulation blocker, and it opened nothing from any of them. These tests
pin the properties that make the new hand-off safe:

* proposing writes nothing — a queue nobody asked for is how a remediation surface gets
  muted;
* the proof is written down when the work opens, not when someone claims it is done;
* a conflict is closed by the dispute no longer being held, never by picking a winner;
* a fact that disappears is ``PROOF_UNAVAILABLE``, not "fixed";
* a HUMAN-proof item is never auto-closed;
* re-proposing refreshes one item instead of filing a second ticket;
* the lifecycle now computes REMEDIATE and RE_DISCOVER from the work table.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import estate_lifecycle, estate_observations as history, estate_remediation as remediation
from shared_models.estate_graph import build_graph


@pytest.fixture
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


def _conflicting_payload() -> dict:
    """One asset with two currently-asserted algorithms — a REAL conflict."""
    return {
        "estate": "Synthetic Bank",
        "scope": "production",
        "assets": [{"ref": "api", "type": "APPLICATION", "name": "Payment API"}],
        "evidence": [
            {"source": "agent", "evidence_type": "RUNTIME_OBSERVED", "target": "api",
             "layer": "APPLICATION", "facts": {"algorithm": "AES-256-GCM"}},
            {"source": "linux-static", "evidence_type": "CONFIGURED", "target": "api",
             "layer": "APPLICATION", "facts": {"algorithm": "AES-128-CBC"}},
        ],
        "relationships": [],
        "crypto": [
            {"asset": "api", "algorithm": "AES-256-GCM", "usage_state": "OBSERVED",
             "layer": "APPLICATION"},
            {"asset": "api", "algorithm": "AES-128-CBC", "usage_state": "CONFIGURED",
             "layer": "APPLICATION"},
        ],
    }


def _held_dispute(db):
    """Persist a fact with two CURRENT values, which is what a conflict item proves against."""
    graph = build_graph(_conflicting_payload())
    history.sync(db, graph, tenant_id=None)
    return graph


def _merge_to_one_value(db, asset_id: str, fact_type: str, value: str):
    """Retire every other value, the way a real resolution would be observed."""
    from db.models.estate_catalog import EstateObservationRecord

    rows = list(db.execute(select(EstateObservationRecord)).scalars())
    for row in rows:
        if row.asset_id == asset_id and row.fact_type == fact_type:
            row.lifecycle_state = "CURRENT" if row.value == value else "HISTORICAL"
    db.commit()


def _work(db):
    from db.models.estate_remediation_work import EstateRemediationWork

    return list(db.execute(select(EstateRemediationWork)).scalars())


def test_proposing_writes_nothing(db):
    _held_dispute(db)

    report = remediation.propose(db, tenant_id=None, persist=False)

    assert report["persisted"] is False
    assert report["count"] >= 1, "a held dispute is work"
    assert _work(db) == [], "a proposal must not create a queue"


def test_the_proof_is_written_down_when_the_work_opens(db):
    _held_dispute(db)

    report = remediation.propose(db, tenant_id=None, persist=True, opened_by="operator-1")

    rows = _work(db)
    assert len(rows) == report["created"]
    for row in rows:
        assert row.proof_kind in {remediation.PROOF_COVERAGE_DISPUTE,
                                  remediation.PROOF_COLLECTOR_STATUS,
                                  remediation.PROOF_HUMAN}
        assert row.proof_expected, "an item with no expected observation cannot be closed"
        assert row.status == remediation.OPEN
        assert row.opened_by == "operator-1"
        assert row.not_proven, "an item must say what proving it does not prove"


def test_a_conflict_becomes_one_item_not_one_per_value(db):
    _held_dispute(db)

    first = remediation.propose(db, tenant_id=None, persist=True)
    assert first["created"] >= 1
    second = remediation.propose(db, tenant_id=None, persist=True)

    assert second["created"] == 0, "re-proposing the same disagreement filed a new item"
    assert second["refreshed"] >= 1


def test_resolving_a_dispute_closes_the_item_by_citation(db):
    graph = _held_dispute(db)
    remediation.propose(db, tenant_id=None, persist=True)
    asset_id = str(graph.assets()[0]["asset_id"])

    _merge_to_one_value(db, asset_id, "crypto:algorithm", "AES-256-GCM")
    report = remediation.reconcile(db, tenant_id=None)

    proven = [item for item in report["proven"] if item["source"] == remediation.CONFLICT]
    assert proven, report
    for item in proven:
        assert item["proof_observation_id"], "a closure must cite the observation row"
        assert item["proof_evidence_id"], "a closure must cite the evidence"
        assert item["proof"]["kind"] == remediation.PROOF_COVERAGE_DISPUTE


def test_a_vanished_fact_is_not_a_fix(db):
    graph = _held_dispute(db)
    remediation.propose(db, tenant_id=None, persist=True)
    asset_id = str(graph.assets()[0]["asset_id"])

    from db.models.estate_catalog import EstateObservationRecord

    for row in db.execute(select(EstateObservationRecord)).scalars():
        if row.asset_id == asset_id:
            row.lifecycle_state = "HISTORICAL"
    db.commit()

    report = remediation.reconcile(db, tenant_id=None)

    assert report["proven"] == [], "a fact nobody asserts any more is not a repaired estate"
    assert report["proof_unavailable"], report
    assert all(row.status == remediation.OPEN for row in _work(db))


def test_an_unchanged_dispute_stays_open_and_counts_the_attempt(db):
    _held_dispute(db)
    remediation.propose(db, tenant_id=None, persist=True)

    report = remediation.reconcile(db, tenant_id=None)

    assert report["proven"] == []
    assert report["still_open"]
    assert all(row.reconcile_attempts == 1 for row in _work(db))


def test_a_human_proof_item_is_never_auto_closed(db):
    simulation = {
        "simulation_id": "sim-1",
        "blockers": [{"kind": "UNRESOLVED_RELATIONSHIP", "asset_id": "api",
                      "detail": "an assumed edge could hide a larger radius"}],
    }

    report = remediation.propose(db, simulation=simulation, tenant_id=None, persist=True)
    assert report["by_source"].get(remediation.SIMULATION_BLOCKER) == 1

    reconciled = remediation.reconcile(db, tenant_id=None)

    assert reconciled["proven"] == []
    reasons = " ".join(item["reason"] for item in reconciled["still_open"])
    assert "assertion" in reasons
    assert all(row.status == remediation.OPEN for row in _work(db))


def test_coverage_loss_opens_work_and_a_clean_plane_closes_it(db):
    class _Plane:
        def __init__(self, status):
            self.status = status

        def assets(self):
            return []

        def evidence(self):
            return []

        def conflicts(self):
            return []

        def coverage(self):
            return {"collectors": [
                {"plane": "HSM", "status": self.status, "expected": 4,
                 "collected": 0 if self.status == "FAILED" else 4,
                 "reason": "KMIP endpoint refused"},
            ]}

    proposed = remediation.propose(db, graph=_Plane("FAILED"), tenant_id=None, persist=True)
    assert proposed["by_source"].get(remediation.COVERAGE_LOSS) == 1

    still = remediation.reconcile(db, graph=_Plane("FAILED"), tenant_id=None)
    assert still["proven"] == []

    closed = remediation.reconcile(db, graph=_Plane("COMPLETE"), tenant_id=None)
    assert [item["subject_id"] for item in closed["proven"]] == ["HSM"]


def test_the_lifecycle_computes_remediate_and_rediscover(db):
    graph = _held_dispute(db)
    remediation.propose(db, tenant_id=None, persist=True)

    before = estate_lifecycle.survey(db, None, tenant_id=None)
    remediate = next(p for p in before["phases"] if p["phase"] == "REMEDIATE")
    assert remediate["status"] == estate_lifecycle.PARTIAL, remediate
    assert remediate["observed"]["work_items"] >= 1

    _merge_to_one_value(db, str(graph.assets()[0]["asset_id"]), "crypto:algorithm", "AES-256-GCM")
    remediation.reconcile(db, tenant_id=None)

    after = estate_lifecycle.survey(db, None, tenant_id=None)
    remediate = next(p for p in after["phases"] if p["phase"] == "REMEDIATE")
    rediscover = next(p for p in after["phases"] if p["phase"] == "RE_DISCOVER")
    assert remediate["status"] == estate_lifecycle.CONNECTED, remediate
    assert rediscover["status"] == estate_lifecycle.CONNECTED, rediscover
    assert rediscover["observed"]["work_proven_by_observation"] >= 1


def test_the_limits_travel_with_the_answer(db):
    _held_dispute(db)

    report = remediation.propose(db, tenant_id=None)

    text = " ".join(report["limits"])
    assert "cannot execute a fix" in text
    assert "not a causal proof" in text


# -- API surface ------------------------------------------------------------ #

import test_network_protocol_safety as shared_api_local  # noqa: E402

api_fixture = pytest.fixture(name="api")(shared_api_local.client.__wrapped__)

BASE = "/api/v1/estate/evidence"
LIST_URL = f"{BASE}/twin/remediation"
PROPOSE_URL = f"{BASE}/twin/remediate"
RECONCILE_URL = f"{BASE}/twin/remediation/reconcile"


def _algorithm_payload() -> dict:
    """Two planes asserting two algorithms: the dispute the history files under a fact."""
    return {
        "estate": "Synthetic Bank",
        "assets": [{"ref": "api", "type": "APPLICATION", "name": "Payment API",
                    "environment": "production"}],
        "evidence": [
            {"source": "source-1", "collector": "collector-1",
             "evidence_type": "STATIC_OBSERVED", "target": "api", "layer": "PLATFORM",
             "facts": {"algorithm": "AES-128"}},
            {"source": "source-2", "collector": "collector-2",
             "evidence_type": "RUNTIME_OBSERVED", "target": "api", "layer": "APPLICATION",
             "facts": {"algorithm": "AES-256-GCM"}},
        ],
        "relationships": [],
        "crypto": [],
    }


def test_the_proposal_endpoint_writes_nothing_without_persist(api):
    client, session = api
    history.sync(session, build_graph(_algorithm_payload()), tenant_id=None)

    response = client.post(PROPOSE_URL, json={})

    assert response.status_code == 200
    body = response.json()
    assert body["persisted"] is False
    assert body["candidates"], "a held conflict is work"
    assert body["limits"]
    assert client.get(LIST_URL).json()["count"] == 0


def test_persisting_opens_the_work_and_lists_it(api):
    client, session = api
    history.sync(session, build_graph(_algorithm_payload()), tenant_id=None)

    proposed = client.post(PROPOSE_URL, json={"persist": True}).json()
    listed = client.get(LIST_URL).json()

    assert proposed["persisted"] is True
    assert listed["count"] == proposed["created"]
    assert listed["by_status"] == {remediation.OPEN: listed["count"]}
    item = listed["items"][0]
    assert item["proof"]["kind"] in {remediation.PROOF_COVERAGE_DISPUTE,
                                     remediation.PROOF_COLLECTOR_STATUS,
                                     remediation.PROOF_HUMAN}
    assert item["not_proven"]


def test_reconcile_without_a_proof_leaves_the_item_open(api):
    client, session = api
    history.sync(session, build_graph(_algorithm_payload()), tenant_id=None)
    client.post(PROPOSE_URL, json={"persist": True})

    reconciled = client.post(RECONCILE_URL).json()

    assert reconciled["proven"] == []
    assert reconciled["still_open"]
    assert client.get(LIST_URL).json()["by_status"][remediation.OPEN] >= 1


def test_the_routes_say_what_they_cannot_do(api):
    client, _session = api

    body = client.get(LIST_URL).json()

    text = " ".join(body["limits"])
    assert "cannot execute a fix" in text
    assert body["meaning"]
