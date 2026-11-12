"""Scanner → digital-twin flow: a projection must be readable on the twin.

The chain this pins, end to end, with no second seeding step:

    scanner observation
      → monitor projection (the same explicit-field CBOM projection the
        API live runner uses: only records the scanner actually reported)
      → CryptoRepository: tenant-qualified current state + immutable journal
      → the twin read surface: overview, fidelity, timeline

and the flow's honesty properties: the current state is replaced on
re-projection while the journal only ever grows, and evidence references
travel with the observations that carry them. The twin must show what the
scanner reported — nothing invented in between.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.main import create_app
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.models.crypto_live import CryptoLiveEventRow, CryptoLiveState
from db.repositories.user_repository import UserRepository


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def client(session):
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    app = create_app()
    c = TestClient(app)
    token = SessionManager().create_session("viewer", roles=["viewer"])
    repo.create_session(token, "viewer",
                        datetime.now(timezone.utc) + timedelta(hours=1),
                        ip="127.0.0.1")
    session.commit()
    c.cookies.set("cryptoscan_session", token)
    return c


class _Target:
    """The monitor adapter reads exactly these attributes off a target row."""

    def __init__(self, *, target_id="runtime-host-1", target_type="RUNTIME", tenant_id=None):
        self.id = target_id
        self.target_type = target_type
        self.tenant_id = tenant_id


def _runtime_observation():
    return {
        "scanner": "runtime",
        "summary": {"processes": 1},
        "issues": [],
        "data": {
            "findings": [
                {
                    "name": "aes-256-gcm",
                    "crypto": {"algorithm": "AES-256-GCM", "mode": "GCM"},
                    "evidence_reference": "sha256:deadbeef",
                }
            ],
            "libraries": [{"name": "openssl", "version": "3.0.2"}],
        },
    }


def _project(session, result=None, target=None):
    from worker.monitor.realtime_projection import persist_monitor_projection

    persist_monitor_projection(target or _Target(),
                               result or _runtime_observation(), session)
    session.commit()


ALGO_STATE_ID = "platform:monitor:runtime:algorithm:AES-256-GCM:"
LIB_STATE_ID = "platform:monitor:runtime:library:openssl:3.0.2"


def test_projection_lands_in_the_store_with_exact_namespaced_identity(session):
    _project(session)
    states = {s.asset_id: s for s in session.query(CryptoLiveState)}
    assert set(states) == {ALGO_STATE_ID, LIB_STATE_ID}
    assert states[ALGO_STATE_ID].algorithms == ["AES-256-GCM"]
    assert states[LIB_STATE_ID].libraries[0]["name"] == "openssl"
    # the journal carries the scanner's own evidence pointer, never a guessed one
    events = session.query(CryptoLiveEventRow).all()
    assert events
    algo_event = next(e for e in events if e.asset_id == ALGO_STATE_ID)
    assert algo_event.event_type == "MONITOR_OBSERVED"
    assert algo_event.source == "runtime"
    assert algo_event.payload["component"]["evidence_reference"] == "sha256:deadbeef"


def test_twin_read_surface_shows_the_projection(client, session):
    _project(session)

    overview = client.get("/api/v1/digital-twin").json()
    assert overview["twin_assets"] == 2

    fidelity = client.get("/api/v1/digital-twin/fidelity").json()
    assert fidelity["twin"]["assets"] == 2
    assert fidelity["twin"]["journal_events"] == 2

    timeline = client.get(f"/api/v1/digital-twin/timeline/{ALGO_STATE_ID}").json()
    assert timeline["asset_id"] == ALGO_STATE_ID
    assert timeline["current_cbom_version"] == 1
    assert [e["event_type"] for e in timeline["events"]] == ["MONITOR_OBSERVED"]
    assert timeline["events"][0]["source"] == "runtime"


def test_reprojection_replaces_current_state_but_journal_only_grows(session):
    _project(session)
    assert session.query(CryptoLiveState).count() == 2
    # journal rows: 2 MONITOR_OBSERVED (algorithm, library) + 1 MONITOR_FINDING
    # (the finding is journalled under the target's namespace, not as state)
    journal_before = session.query(CryptoLiveEventRow).count()
    assert journal_before == 3

    # second pass on the same target reports only the library — the algorithm
    # observation is absent, so the current state must not keep pretending it
    # was observed again, while its journal history stays immutable.
    _project(session, result={
        "scanner": "runtime",
        "summary": {"processes": 1},
        "issues": [],
        "data": {"libraries": [{"name": "openssl", "version": "3.0.2"}]},
    })
    states = {s.asset_id for s in session.query(CryptoLiveState)}
    assert states == {LIB_STATE_ID}
    assert session.query(CryptoLiveEventRow).count() == journal_before + 1
    assert session.query(CryptoLiveEventRow).filter_by(asset_id=ALGO_STATE_ID).count() == 1


def test_twin_timeline_still_holds_replaced_history(client, session):
    _project(session)
    _project(session, result={
        "scanner": "runtime",
        "summary": {"processes": 1},
        "issues": [],
        "data": {"libraries": [{"name": "openssl", "version": "3.0.2"}]},
    })

    # the algorithm row is no longer in the current state...
    overview = client.get("/api/v1/digital-twin").json()
    assert overview["twin_assets"] == 1
    # ...but the journal still answers time-travel for it
    timeline = client.get(f"/api/v1/digital-twin/timeline/{ALGO_STATE_ID}").json()
    assert [e["event_type"] for e in timeline["events"]] == ["MONITOR_OBSERVED"]
