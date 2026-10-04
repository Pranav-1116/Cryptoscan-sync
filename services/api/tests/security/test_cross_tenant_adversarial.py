"""Adversarial cross-tenant probes at the HTTP boundary.

The existing cross-tenant suite covers the scan listing surface. This battery
attacks the seams an attacker would actually try once the obvious listing is
closed:

* the **graph routes** — before the isolation gate, a healthy Bolt connection
  handed every tenant the same global Neo4j store (blast radius, hotspots,
  vendor chains over *every* tenant's inventory, plus a volume oracle via
  global ``counts()``);
* **scan transfer import** — a pack claiming another tenant's ownership must
  not import rows into that tenant's namespace (nor into the shared platform
  estate);
* **object existence oracles** — foreign ids must be 404 absence, not 403
  confirmation, on every sub-resource of a scan;
* the **SSE event filter** — the visibility predicate applied to replay and
  live delivery, including the platform-admin and unowned-event edges.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.system import System
from db.tenancy import install_tenant_guard, tenant_scope

BANK_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
BANK_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
AUDITOR_KEY = "test-auditor-key"


@pytest.fixture()
def db_session(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("AUDITOR_API_KEY", AUDITOR_KEY)
    install_tenant_guard()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()
    engine.dispose()


def _seed_scan(session, target: str, tenant_id: str) -> Scan:
    scan = Scan(id=f"scan-{target}", target_location=target, status="COMPLETED",
                tenant_id=tenant_id, scan_start=datetime.now(timezone.utc))
    session.add(scan)
    session.commit()
    return scan


def _seed_systems(session) -> None:
    session.add(System(name="Bank A core banking", tenant_id=BANK_A, environment="prod"))
    session.add(System(name="Bank B trading desk", tenant_id=BANK_B, environment="prod"))
    session.commit()


def _client(db_session) -> TestClient:
    from api.config.settings import get_settings
    from api.dependencies import get_current_user, get_db_session
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "analyst"
    app.dependency_overrides[get_db_session] = lambda: (yield db_session)
    return TestClient(app)


class RecordingDriver:
    """A healthy Neo4j driver that records every Bolt statement."""

    def __init__(self):
        self.log: list[str] = []

    class _Session:
        def __init__(self, log):
            self._log = log

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def close(self):
            return None

        def run(self, query, *args, **kwargs):
            self._log.append(query)
            class _R:
                def single(self):
                    return {"ok": 1}
                def __iter__(self):
                    return iter([{"ok": 1}])
            return _R()

    def session(self, database=None):
        return RecordingDriver._Session(self.log)


# --------------------------------------------------------------------- #
# graph routes: the global Neo4j store must never serve a tenant
# --------------------------------------------------------------------- #

def test_graph_route_serves_the_tenant_slice_and_never_the_global_store(db_session, monkeypatch):
    _seed_systems(db_session)
    from graph_engine.core import facade as graph_facade
    from graph_engine.connection import health_check

    driver = RecordingDriver()
    monkeypatch.setattr(graph_facade, "get_driver", lambda: driver)
    monkeypatch.setattr(health_check, "get_driver", lambda: driver)

    client = _client(db_session)
    with client, tenant_scope(BANK_A):
        r = client.get("/api/v1/graph", headers={"Authorization": "Bearer t"})

    assert r.status_code == 200, r.text
    body = r.text
    assert "Bank A core banking" in body
    assert "Bank B trading desk" not in body, "another tenant's system leaked through /graph"
    assert r.json()["backend"] == "memory-tenant-isolated"
    # Only health PINGs may reach Bolt — never a data read or write.
    data_calls = [q for q in driver.log if "RETURN 1" not in q]
    assert data_calls == [], f"scoped graph request issued tenant-visible Bolt statements: {data_calls}"


def test_graph_sync_under_a_scope_does_not_write_the_shared_store(db_session, monkeypatch):
    _seed_systems(db_session)
    from graph_engine.core import facade as graph_facade
    from graph_engine.connection import health_check

    driver = RecordingDriver()
    monkeypatch.setattr(graph_facade, "get_driver", lambda: driver)
    monkeypatch.setattr(health_check, "get_driver", lambda: driver)

    client = _client(db_session)
    with client, tenant_scope(BANK_A):
        r = client.post("/api/v1/graph/sync", headers={"Authorization": "Bearer t"})

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["synced"] is False
    assert body.get("reason") == "tenant_isolated" or body.get("backend") == "memory"
    data_calls = [q for q in driver.log if "RETURN 1" not in q]
    assert data_calls == [], f"scoped graph sync issued Bolt write statements: {data_calls}"


# --------------------------------------------------------------------- #
# scan transfer import: ownership cannot be claimed by the payload
# --------------------------------------------------------------------- #

def _forge_pack(tenant_claim: str) -> dict:
    """A digest-valid transfer pack whose scan dict claims another tenant."""
    from evidence.pack.scan_transfer import export_transfer

    scan = {
        "scan_id": "scan-forged-import",
        "scan_start": datetime.now(timezone.utc).isoformat(),
        "scan_end": datetime.now(timezone.utc).isoformat(),
        "scanner_id": "static-java-scanner-v0.1",
        "scanner_version": "0.1.0",
        "target_type": "LOCAL_DIRECTORY",
        "target_location": "bank-b-core",
        "status": "COMPLETED",
        "tenant_id": tenant_claim,  # the smuggled claim
    }
    records = [{
        "content_hash": "a" * 64,
        "chain_hash": "a" * 64,
        "chain_position": 0,
        "algorithm": "RSA-2048",
        "confidence": "HIGH",
        "file_path": "src/Main.java",
        "line_number": 42,
        "finding_data": {"finding": {"crypto": {"algorithm": "RSA-2048"}}},
    }]
    return export_transfer(scan=scan, records=records)


def test_scan_transfer_import_attributes_rows_to_the_importer(db_session):
    pack = _forge_pack(BANK_B)

    client = _client(db_session)
    with client, tenant_scope(BANK_A):
        r = client.post(
            "/api/v1/scans/import",
            json=pack,
            headers={"Authorization": "Bearer t", "X-Auditor-Key": AUDITOR_KEY},
        )

    assert r.status_code == 200, r.text
    assert r.json()["imported"] is True
    scan = db_session.get(Scan, "scan-forged-import")
    assert scan is not None
    assert scan.tenant_id == BANK_A, "imported scan must belong to the importing tenant"
    rows = db_session.query(EvidenceRecord).filter_by(scan_id="scan-forged-import").all()
    assert rows and all(row.tenant_id == BANK_A for row in rows), (
        "imported evidence must belong to the importing tenant"
    )


def test_scan_transfer_import_is_idempotent_per_tenant(db_session):
    pack = _forge_pack(BANK_B)
    client = _client(db_session)
    headers = {"Authorization": "Bearer t", "X-Auditor-Key": AUDITOR_KEY}
    with client, tenant_scope(BANK_A):
        first = client.post("/api/v1/scans/import", json=pack, headers=headers)
        second = client.post("/api/v1/scans/import", json=pack, headers=headers)
    assert first.json()["imported"] is True
    assert second.json()["imported"] is False
    assert second.json()["reason"] == "scan_already_present"


# --------------------------------------------------------------------- #
# absence, not confirmation: foreign ids on sub-resources
# --------------------------------------------------------------------- #

@pytest.mark.parametrize("path", [
    "/api/v1/scans/{scan_id}/transfer",
    "/api/v1/scans/{scan_id}/quantum",
    "/api/v1/scans/{scan_id}/remediation",
])
def test_foreign_scan_subresources_are_absence_not_403(db_session, path):
    other = _seed_scan(db_session, "bank-b-core", BANK_B)
    _seed_scan(db_session, "bank-a-core", BANK_A)

    client = _client(db_session)
    with client, tenant_scope(BANK_A):
        r = client.get(path.format(scan_id=other.id),
                       headers={"Authorization": "Bearer t", "X-Auditor-Key": AUDITOR_KEY})
    assert r.status_code == 404, f"{path}: foreign scan must be absence, got {r.status_code}"
    assert "bank-b" not in r.text.lower()


def test_own_scan_subresources_remain_reachable(db_session):
    mine = _seed_scan(db_session, "bank-a-core", BANK_A)
    client = _client(db_session)
    with client, tenant_scope(BANK_A):
        r = client.get(f"/api/v1/scans/{mine.id}/quantum",
                       headers={"Authorization": "Bearer t"})
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------- #
# SSE visibility predicate
# --------------------------------------------------------------------- #

def _sse_visible(event, tenant_id, is_platform_admin=False):
    from api.routers.events import _visible_to_tenant

    return _visible_to_tenant(event, tenant_id, is_platform_admin)


def test_owned_event_is_invisible_to_another_tenant():
    event = {"type": "scan.completed", "tenant_id": BANK_B, "payload": {}}
    assert _sse_visible(event, BANK_A) is False
    assert _sse_visible(event, BANK_B) is True


def test_unowned_platform_event_is_visible_to_every_tenant():
    event = {"type": "graph.updated", "tenant_id": None, "payload": {}}
    assert _sse_visible(event, BANK_A) is True
    assert _sse_visible(event, BANK_B) is True


def test_owned_event_is_hidden_from_an_unscoped_admin_connection():
    """An admin who has not selected a tenant sees platform traffic only."""
    event = {"type": "scan.completed", "tenant_id": BANK_B, "payload": {}}
    assert _sse_visible(event, None, is_platform_admin=True) is False


def test_payload_level_tenant_claim_cannot_spoof_visibility():
    """Ownership falls back to the payload only when the frame is unowned."""
    owned = {"type": "e", "tenant_id": BANK_A, "payload": {"tenant_id": BANK_B}}
    assert _sse_visible(owned, BANK_B) is False, "payload must not override the frame's owner"
    unowned = {"type": "e", "tenant_id": None, "payload": {"tenant_id": BANK_B}}
    assert _sse_visible(unowned, BANK_B) is True
    assert _sse_visible(unowned, BANK_A) is False


def test_injected_remote_frame_is_filtered_before_the_queue():
    """Redis-federated frames keep their owner; a tenant's subscriber queue
    only receives events its filter accepts (bus-level, not HTTP-level)."""
    import asyncio

    from api.events.bus import EventBus

    async def scenario() -> list[dict]:
        bus = EventBus()
        sub = bus.subscribe(lambda event: _sse_visible(event, BANK_A))
        try:
            bus.inject_remote({"type": "scan.completed", "tenant_id": BANK_B, "payload": {}})
            bus.inject_remote({"type": "graph.updated", "tenant_id": None, "payload": {}})
            await asyncio.sleep(0)  # let call_soon_threadsafe callbacks run
            await asyncio.sleep(0)
            queued = []
            while not sub.queue.empty():
                queued.append(sub.queue.get_nowait())
            return queued
        finally:
            bus.unsubscribe(sub)

    queued = asyncio.run(scenario())
    assert [e["type"] for e in queued] == ["graph.updated"], (
        "another tenant's federated event reached a subscriber queue"
    )
