"""The twin's loop, phase by phase (spec 94 §2).

The specification draws a loop that ends where it starts. A product that publishes such a
diagram is tempted to colour every box the same and let the reader assume it closes; these
tests hold this module to the opposite, and to three distinctions that a status field
alone would hide:

* **an empty estate is not a broken loop** — nothing has observed anything, so the phases
  report ``NOT_STARTED`` with a zero count behind each, rather than an optimistic status;
* **an open queue is not a fix** — ``REMEDIATE`` is ``NOT_STARTED`` when the twin has
  opened nothing, ``PARTIAL`` once work exists, and ``CONNECTED`` only when a cited
  observation closed one;
* **``loop_closed`` is computed** — every phase CONNECTED, no hand-maintained flag — and
  ``first_break`` names the earliest phase worth building next.

The status vocabulary has three meanings that must never be merged: configured but not
proven is ``PARTIAL``, and a phase that exists but receives nothing says so in ``gap``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import estate_catalog as catalog
from api import estate_lifecycle as lifecycle
from api import estate_observations as history
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"
LIFECYCLE_URL = f"{BASE}/twin/lifecycle"

_STATUSES = {"CONNECTED", "PARTIAL", "NOT_CONNECTED", "NOT_STARTED"}


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


def _payload() -> dict:
    return {
        "estate": "Synthetic Bank",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "Payment API",
             "environment": "production"},
            {"ref": "hsm", "type": "HSM", "name": "HSM-04", "environment": "production",
             "attributes": {"vendor": "Thales"}},
        ],
        "evidence": [
            {"evidence_id": "ev-1", "source": "sbom", "collector": "sbom-parser",
             "evidence_type": "STATIC_OBSERVED", "target": "api", "layer": "APPLICATION",
             "facts": {"algorithm": "AES-256-GCM", "library": "OpenSSL 3.0.13"}},
            {"evidence_id": "ev-2", "source": "hsm-audit", "collector": "hsm-audit",
             "evidence_type": "RUNTIME_OBSERVED", "target": "hsm", "layer": "HSM",
             "facts": {"firmware": "7.8.0"}},
            {"evidence_id": "ev-3", "source": "cmdb", "collector": "cmdb",
             "evidence_type": "CONFIGURED", "target": "api", "layer": "APPLICATION",
             "facts": {"owner": "payments-team"}},
        ],
        "relationships": [
            {"subject": "api", "predicate": "uses_hsm", "object": "hsm",
             "basis": "PKCS11_REFERENCE", "evidence_ids": ["ev-2"]},
        ],
    }


def _by_phase(body: dict) -> dict:
    return {entry["phase"]: entry for entry in body["phases"]}


def test_every_phase_is_reported_in_the_order_the_spec_draws_it(db):
    body = lifecycle.survey(db, None, tenant_id=None)

    assert [entry["phase"] for entry in body["phases"]] == list(lifecycle.PHASE_ORDER)
    assert set(body["by_status"]) == _STATUSES
    assert body["schema"] == "cryptoscan.estate-lifecycle/1"
    for entry in body["phases"]:
        assert entry["status"] in _STATUSES
        assert entry["question"].endswith("?")
        assert entry["backed_by"]


def test_an_empty_estate_is_not_started_rather_than_broken(db):
    body = lifecycle.survey(db, None, tenant_id=None)
    phases = _by_phase(body)

    assert phases["DISCOVER"]["status"] == "NOT_STARTED"
    assert phases["DISCOVER"]["observed"]["recorded_facts"] == 0
    assert "no observation has ever been recorded" in phases["DISCOVER"]["detail"]
    assert phases["MODEL"]["status"] == "NOT_STARTED"
    assert phases["SNAPSHOT"]["status"] == "NOT_STARTED"
    # an unwalked loop is not a closed one
    assert body["loop_closed"] is False
    assert body["first_break"] == "MONITOR"


def test_an_observed_estate_walks_the_first_half_of_the_loop(db):
    graph = build_graph(_payload())
    history.sync_all(db, graph, tenant_id=None)
    catalog.sync(db, graph, tenant_id=None)

    phases = _by_phase(lifecycle.survey(db, graph, tenant_id=None))

    assert phases["DISCOVER"]["status"] == "CONNECTED"
    assert phases["IDENTIFY"]["observed"]["assets"] == 2
    assert phases["EVIDENCE"]["observed"]["evidence_records"] == 3
    assert phases["NORMALIZE"]["status"] == "CONNECTED"
    assert phases["MODEL"]["status"] == "CONNECTED"
    assert phases["CORRELATE"]["status"] == "CONNECTED"


def test_remediation_with_nothing_to_do_is_not_started_rather_than_broken(db):
    """The hand-off exists; this estate simply has not asked it for anything yet."""
    graph = build_graph(_payload())
    history.sync(db, graph, tenant_id=None)

    phases = _by_phase(lifecycle.survey(db, graph, tenant_id=None))

    assert phases["REMEDIATE"]["status"] == "NOT_STARTED"
    assert phases["REMEDIATE"]["observed"]["work_items"] == 0
    assert "nothing has asked for any yet" in phases["REMEDIATE"]["detail"]
    assert "closing a HUMAN-proof item is still an assertion" in phases["REMEDIATE"]["gap"]


def test_monitoring_with_a_schedule_that_has_never_run_is_partial(db):
    from datetime import datetime, timezone

    from db.models.estate_schedule import EstateSchedule

    db.add(EstateSchedule(
        name="nightly", scope="production", estate="default",
        interval_minutes=1440, enabled=True,
        next_run_at=datetime.now(timezone.utc), created_by="ops",
    ))
    db.commit()
    graph = build_graph(_payload())
    history.sync(db, graph, tenant_id=None)

    phases = _by_phase(lifecycle.survey(db, graph, tenant_id=None))

    assert phases["MONITOR"]["status"] == "PARTIAL"
    assert phases["MONITOR"]["observed"]["enabled_schedules"] == 1
    assert "not proven" in phases["MONITOR"]["detail"]


def test_without_a_schedule_the_twin_says_nothing_is_monitoring(db):
    graph = build_graph(_payload())
    history.sync(db, graph, tenant_id=None)

    phases = _by_phase(lifecycle.survey(db, graph, tenant_id=None))

    assert phases["MONITOR"]["status"] == "NOT_CONNECTED"
    assert "nothing is scheduled" in phases["MONITOR"]["detail"]


def test_the_loop_never_claims_to_close_while_remediation_is_unwired(db):
    graph = build_graph(_payload())
    history.sync(db, graph, tenant_id=None)

    body = lifecycle.survey(db, graph, tenant_id=None)

    assert body["loop_closed"] is False
    assert body["first_break"] in {"MONITOR", "REMEDIATE"}
    assert "the loop is reported as closed only when every phase is CONNECTED" in body["meaning"]


def test_no_constant_can_make_the_loop_look_closed(db):
    """`loop_closed` is computed from the phases, so no flag flip can declare success."""
    graph = build_graph(_payload())
    history.sync(db, graph, tenant_id=None)
    body = lifecycle.survey(db, graph, tenant_id=None)

    connected = sum(1 for entry in body["phases"] if entry["status"] == "CONNECTED")

    assert body["loop_closed"] is (connected == len(body["phases"]))
    assert body["by_status"]["CONNECTED"] == connected


def test_the_limits_name_what_a_status_cannot_prove(db):
    body = lifecycle.survey(db, None, tenant_id=None)

    assert any("NOT_STARTED is not a defect" in line for line in body["limits"])
    assert any("never that what it wrote is correct" in line for line in body["limits"])


def test_the_endpoint_answers_from_an_empty_estate_without_pretending(api):
    client, session = api

    response = client.get(LIFECYCLE_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "cryptoscan.estate-lifecycle/1"
    assert body["loop_closed"] is False
    assert len(body["phases"]) == len(lifecycle.PHASE_ORDER)


def test_the_endpoint_reads_the_recorded_facts(api):
    client, session = api
    graph = build_graph(_payload())
    history.sync_all(session, graph, tenant_id=None)
    catalog.sync(session, graph, tenant_id=None)

    body = client.get(LIFECYCLE_URL).json()
    phases = _by_phase(body)

    assert phases["DISCOVER"]["observed"]["recorded_facts"] > 0
    assert phases["IDENTIFY"]["observed"]["assets"] == 2
    assert body["by_status"]["CONNECTED"] >= 4
