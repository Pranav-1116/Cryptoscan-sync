"""Integration: blast-radius from live dependency edges + periodic CBOM tick.

Exercises the deterministic automation engine against live DB inventory rather
than client-supplied graphs (no AI/ML).
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


def _token():
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=["superadmin"])


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "automation_live_integration_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {_token()}"
        yield c


class TestLiveBlastRadius:
    def test_live_dependency_edges_are_traversed(self, client):
        from db.connection.session import SessionLocal
        from db.models.system import System
        from db.models.system_dependency import SystemDependency

        db = SessionLocal()
        # origin app -> downstream API -> business service
        origin = System(name="origin-app")
        api_sys = System(name="downstream-api")
        biz = System(name="checkout-service", criticality="MISSION_CRITICAL")
        db.add_all([origin, api_sys, biz])
        db.flush()
        db.add_all([
            SystemDependency(parent_id=origin.id, child_id=api_sys.id, relation="calls"),
            SystemDependency(parent_id=api_sys.id, child_id=biz.id, relation="serves"),
        ])
        db.commit()
        origin_id = origin.id
        biz_id = biz.id
        db.close()

        r = client.post(f"{API}/automation/blast-radius",
                        json={"origin": origin_id, "use_live": True})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["edges_source"] == "live_system_dependencies+posted"
        assert body["live_edge_count"] >= 2
        # the business service must be reachable through the live edges
        assert body["reachable_nodes"] >= 2
        affected_ids = {a["id"] for a in body["affected"]}
        assert biz_id in affected_ids
        # name-based classification maps 'checkout-service' to business_service
        assert body["impact_layers"].get("business_service", 0) >= 1

    def test_live_and_posted_edges_merge(self, client):
        from db.connection.session import SessionLocal
        from db.models.system import System

        db = SessionLocal()
        a = System(name="merge-a")
        b = System(name="merge-b")
        db.add_all([a, b])
        db.flush()
        a_id, b_id = a.id, b.id
        db.commit()
        db.close()

        # posted-only edge between two live systems
        r = client.post(f"{API}/automation/blast-radius", json={
            "origin": a_id,
            "edges": [[a_id, b_id]],
            "use_live": True,
        })
        body = r.json()
        assert r.status_code == 200
        affected_ids = {a["id"] for a in body["affected"]}
        assert b_id in affected_ids
        assert body["edge_count"] >= body["live_edge_count"]


class TestPeriodicCbomTick:
    def test_cbom_tick_dedupes_unchanged_state(self, client):
        # post observations to create v1
        obs1 = [{"component_id": "c1", "algorithm": "AES-256-GCM", "key_size": 256}]
        r1 = client.post(f"{API}/automation/cbom/versions",
                         json={"observations": obs1})
        assert r1.status_code == 201, r1.text
        v1 = r1.json().get("version")

        # identical state -> no new version
        r2 = client.post(f"{API}/automation/cbom/versions",
                         json={"observations": obs1})
        body2 = r2.json()
        assert body2["changed"] is False
        assert body2["version"] == v1

    def test_cbom_tick_versions_change(self, client):
        obs = [{"component_id": "c1", "algorithm": "AES-256-GCM", "key_size": 256},
               {"component_id": "c2", "algorithm": "RSA", "key_size": 4096}]
        r = client.post(f"{API}/automation/cbom/versions", json={"observations": obs})
        body = r.json()
        assert r.status_code == 201
        if body.get("changed"):
            assert len(body.get("added") or []) >= 1

        hist = client.get(f"{API}/automation/cbom/versions").json()
        assert hist["total_count"] >= 1
        # chain: latest has a parent fingerprint
        latest = hist["versions"][0]
        assert latest["fingerprint"]
