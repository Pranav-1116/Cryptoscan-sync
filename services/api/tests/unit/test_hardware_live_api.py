"""24/7 Live Hardware Engine API — events, heartbeats, state, timeline,
state-at, agents, edge sync, RBAC."""

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
from db.repositories.hardware_repository import HardwareRepository
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


def _mint_session(db, username: str, roles: list[str]) -> str:
    manager = SessionManager()
    token = manager.create_session(username, roles=roles)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    UserRepository(db).create_session(token, username, expires, ip="127.0.0.1")
    db.commit()
    return token


@pytest.fixture()
def admin_client(session):
    repo = UserRepository(session)
    repo.create_user("admin", hash_password("x"), ["admin"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(session, "admin", ["admin"]))
    return client


@pytest.fixture()
def viewer_client(session):
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    app = create_app()
    client = TestClient(app)
    client.cookies.set("cryptoscan_session", _mint_session(session, "viewer", ["viewer"]))
    return client


# ── events + state ─────────────────────────────────────────────────────

def test_ingest_discovery_and_read_state(admin_client, session):
    r = admin_client.post("/api/v1/hardware/events", json={
        "event_type": "HARDWARE_DISCOVERED",
        "asset_id": "srv-1", "agent_id": "edge-1", "source": "agent",
        "manufacturer": "Dell", "model": "R760", "device_type": "server",
        "serial_reference": "SN-1",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state_verdict"] == "NEW"
    assert "full_inventory" in body["targeted_actions"]
    assert body["evidence_id"]
    assert body["hbom_version"] == 2

    state = admin_client.get("/api/v1/hardware/state/srv-1")
    assert state.status_code == 200
    assert state.json()["manufacturer"] == "Dell"
    assert state.json()["agent_id"] == "edge-1"

    listing = admin_client.get("/api/v1/hardware/state")
    assert listing.json()["total_count"] == 1


def test_bios_update_pipeline_and_timeline(admin_client):
    admin_client.post("/api/v1/hardware/events", json={
        "event_type": "HARDWARE_DISCOVERED", "asset_id": "srv-1",
        "manufacturer": "Dell", "model": "R760",
    })
    r = admin_client.post("/api/v1/hardware/events", json={
        "event_type": "BIOS_CHANGED", "asset_id": "srv-1",
        "component": "BIOS", "version": "2.19",
    })
    assert r.status_code == 200
    actions = r.json()["targeted_actions"]
    assert "bios_verification" in actions
    assert "pqc_reassessment" in actions

    tl = admin_client.get("/api/v1/hardware/timeline?asset_id=srv-1")
    assert tl.json()["total_count"] == 2

    state = admin_client.get("/api/v1/hardware/state/srv-1").json()
    assert state["firmware"]["BIOS"] == "2.19"
    assert state["previous_state"]["firmware"] == {}


def test_state_at_point_in_time(admin_client):
    admin_client.post("/api/v1/hardware/events", json={
        "event_type": "HARDWARE_DISCOVERED", "asset_id": "srv-1",
        "observed_at": "2026-08-31T10:00:00+00:00",
    })
    admin_client.post("/api/v1/hardware/events", json={
        "event_type": "BIOS_CHANGED", "asset_id": "srv-1", "component": "BIOS",
        "version": "2.18", "observed_at": "2026-08-31T12:30:00+00:00",
    })
    admin_client.post("/api/v1/hardware/events", json={
        "event_type": "TPM_AVAILABLE", "asset_id": "srv-1",
        "tpm": {"present": True, "version": "2.0"},
        "observed_at": "2026-08-31T13:00:00+00:00",
    })
    noon = admin_client.get(
        "/api/v1/hardware/timeline/state-at",
        params={"asset_id": "srv-1", "at": "2026-08-31T12:45:00+00:00"},
    )
    assert noon.status_code == 200
    assert noon.json()["state"]["firmware"]["BIOS"] == "2.18"
    assert noon.json()["state"]["tpm"] is None
    # before discovery -> 404
    early = admin_client.get(
        "/api/v1/hardware/timeline/state-at",
        params={"asset_id": "srv-1", "at": "2026-08-31T09:00:00+00:00"},
    )
    assert early.status_code == 404
    # garbage timestamp -> 422
    bad = admin_client.get(
        "/api/v1/hardware/timeline/state-at",
        params={"asset_id": "srv-1", "at": "not-a-time"},
    )
    assert bad.status_code == 422


def test_heartbeat_and_agent_health(admin_client, session):
    r = admin_client.post("/api/v1/hardware/heartbeats", json={
        "agent_id": "edge-1",
        "last_successful_discovery": "2026-08-31T10:00:00+00:00",
        "event_queue_depth": 2, "event_lag_seconds": 1,
        "agent_health": "HEALTHY", "hardware_count": 5,
    })
    assert r.status_code == 200
    assert r.json()["agent_status"] == "ONLINE"
    agents = admin_client.get("/api/v1/hardware/agents")
    assert agents.json()["total_count"] == 1
    assert agents.json()["agents"][0]["hardware_count"] == 5
    row = HardwareRepository(session).get_agent("edge-1")
    assert row.event_queue_depth == 2


def test_edge_sync_batch(admin_client):
    r = admin_client.post("/api/v1/hardware/edge/sync", json={
        "agent_id": "edge-9",
        "events": [
            {"event_type": "HARDWARE_DISCOVERED", "asset_id": "srv-a",
             "manufacturer": "HPE", "model": "DL380"},
            {"event_type": "HARDWARE_DISCOVERED", "asset_id": "srv-b",
             "manufacturer": "HPE", "model": "DL380"},
        ],
        "heartbeat": {"agent_id": "edge-9", "hardware_count": 2},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["events_accepted"] == 2
    assert body["ack"] is True
    assert body["heartbeat"]["agent_status"] == "ONLINE"
    state = admin_client.get("/api/v1/hardware/state?agent_id=edge-9")
    assert state.json()["total_count"] == 2


def test_reaction_plan_dry_run(admin_client):
    r = admin_client.post("/api/v1/hardware/reaction-plan?event_type=BIOS_CHANGED")
    assert r.status_code == 200
    plan = r.json()
    assert plan["scope"] == "TARGETED"
    assert "bios_verification" in plan["required_actions"]
    assert "storage re-scan" in plan["explicitly_not_affected"]


def test_hbom_versions_and_incidents(admin_client):
    admin_client.post("/api/v1/hardware/events", json={
        "event_type": "HARDWARE_DISCOVERED", "asset_id": "srv-1",
    })
    admin_client.post("/api/v1/hardware/events", json={
        "event_type": "BIOS_CHANGED", "asset_id": "srv-1",
        "component": "BIOS", "version": "2.19",
    })
    versions = admin_client.get("/api/v1/hardware/hbom/versions")
    assert versions.json()["versions"][-1]["reason"].startswith("BIOS_CHANGED")
    incidents = admin_client.get("/api/v1/hardware/incidents")
    roots = {i["root_type"] for i in incidents.json()["incidents"]}
    assert roots == {"HARDWARE_DISCOVERED", "HARDWARE_CHANGE"}
    risk = admin_client.get("/api/v1/hardware/risk")
    assert len(risk.json()["risks"]) == 1


def test_hbom_document_native_and_cyclonedx(admin_client):
    """deep/26 §5: the generators existed but no API served the document."""
    admin_client.post("/api/v1/hardware/events", json={
        "event_type": "HARDWARE_DISCOVERED", "asset_id": "srv-hbom",
        "manufacturer": "Dell", "model": "R760", "device_type": "server",
        "serial_reference": "SN-HBOM",
    })

    native = admin_client.get("/api/v1/hardware/hbom")
    assert native.status_code == 200
    doc = native.json()
    assert doc["hbomFormat"] == "ZELNX-HBOM"
    assert any(h["bom-ref"] == "hw:srv-hbom" for h in doc["hardware"])

    cd = admin_client.get("/api/v1/hardware/hbom?fmt=cyclonedx")
    assert cd.status_code == 200
    cdoc = cd.json()
    assert cdoc["bomFormat"] == "CycloneDX"
    assert cdoc["specVersion"] == "1.5"
    asset_ids = {p["value"] for c in cdoc["components"]
                 for p in c["properties"] if p["name"] == "asset_id"}
    assert "srv-hbom" in asset_ids

    # invalid format is rejected, not silently defaulted
    bad = admin_client.get("/api/v1/hardware/hbom?fmt=xml")
    assert bad.status_code == 422


def test_rbac_gates_hardware_api(viewer_client, admin_client):
    # viewers can read but never ingest/manage
    r = viewer_client.post("/api/v1/hardware/events", json={
        "event_type": "HARDWARE_DISCOVERED", "asset_id": "srv-1"})
    assert r.status_code == 403
    r2 = viewer_client.post("/api/v1/hardware/heartbeats", json={"agent_id": "e1"})
    assert r2.status_code == 403
    # read surface works for viewers
    assert viewer_client.get("/api/v1/hardware/state").status_code == 200
    assert viewer_client.get("/api/v1/hardware/agents").status_code == 200
    # unknown event type is rejected
    bad = admin_client.post("/api/v1/hardware/events", json={
        "event_type": "NOT_A_REAL_EVENT", "asset_id": "x"})
    assert bad.status_code == 422


def test_catalog_carries_vendor_pqc_refresh(admin_client):
    """The 2026-09 vendor refresh: quantum_resistant_count reflects SHIPPING
    PQC support only (7 keystore HSMs + 2 IBM Z entries + ARM CCA = 10), and
    the flags flow through the catalog entries the Vendor page renders."""
    response = admin_client.get("/api/v1/hardware/catalog")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["count"] >= 60
    assert body["quantum_resistant_count"] == 10
    devices = {d["device"]: d for d in body["devices"]}
    assert devices["Thales Luna HSM"]["quantum_resistant"] is True
    assert "7.9" in devices["Thales Luna HSM"]["notes"]
    assert devices["Thales payShield"]["quantum_resistant"] is False  # roadmap ≠ shipped

    # category filter keeps the count additive-consistent:
    # 7 keystore HSMs + 2 IBM Z entries + ARM CCA = 10 total
    keystore = admin_client.get("/api/v1/hardware/catalog", params={"category": "hardware-keystore"})
    keystore_devices = keystore.json()["devices"]
    assert sum(1 for d in keystore_devices if d["quantum_resistant"]) == 7
