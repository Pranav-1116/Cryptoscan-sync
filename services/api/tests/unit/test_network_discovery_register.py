"""POST /network/discover register=true feeds the due-scan rotation."""

from __future__ import annotations

from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user, get_db_session
from api.main import create_app


@pytest.fixture()
def db_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool
    from db.connection.session import Base
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


class FakeIntelRepo:
    instances: list["FakeIntelRepo"] = []

    def __init__(self, _db):
        self.calls: list[tuple[str, dict]] = []
        FakeIntelRepo.instances.append(self)

    def list_targets(self):
        return []  # no pre-existing targets

    def upsert_target(self, endpoint, **kwargs):
        self.calls.append((endpoint, kwargs))


def _fake_sweep(cidr, ports, timeout=1.5, workers=8):  # noqa: ARG001 — mirrors discover_subnet signature
    return {
        "cidr": cidr,
        "ports": list(ports or []),
        "hosts_checked": 2,
        "candidates": 2,
        "truncated": False,
        "endpoints": ["10.0.0.1:443", "10.0.0.2:8443"],
        "open_count": 2,
    }


@pytest.mark.asyncio
async def test_discover_registers_targets(monkeypatch, db_session):
    import api.routers.network as net_router
    import api.security.scan_admission as admission
    import network_scanner.discovery.subnet_discoverer as subnet_module

    monkeypatch.setattr(subnet_module, "discover_subnet", _fake_sweep)
    FakeIntelRepo.instances = []
    monkeypatch.setattr(net_router, "IntelligenceRepository", FakeIntelRepo)
    # These tests exercise the registration path, not admission: pin the
    # decision (no emergency stop, no OT, sweep inside authorized scope).
    monkeypatch.setattr(admission, "_control_plane_state", lambda: ([], None))
    monkeypatch.setattr(admission, "_ot_declared", lambda: False)
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)
    monkeypatch.setattr(admission, "_authorized_network_scope",
                        lambda: ["10.0.0.0/30"])

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield db_session  # durable receipt uses the real SQL session

    app.dependency_overrides[get_db_session] = _session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/network/discover",
            json={"cidr": "10.0.0.0/30", "ports": [443, 8443], "scan": False, "register": True,
                  "scan_frequency": "hourly"},
        )
    assert response.status_code == 200
    payload = response.json()
    registration = payload["registration"]
    assert registration["registered"] == 2
    assert registration["updated"] == 0
    assert registration["scan_frequency"] == "hourly"
    assert registration["endpoints"] == ["10.0.0.1:443", "10.0.0.2:8443"]

    repo = FakeIntelRepo.instances[0]
    assert [endpoint for endpoint, _kw in repo.calls] == ["10.0.0.1:443", "10.0.0.2:8443"]
    for endpoint, kwargs in repo.calls:
        assert isinstance(kwargs["next_scan_time"], datetime)  # DB column gets a datetime
        assert kwargs["scan_frequency"] == "hourly"
        assert kwargs["enabled"] is True


@pytest.mark.asyncio
async def test_discover_without_register_leaves_rotation_alone(monkeypatch, db_session):
    import api.routers.network as net_router
    import api.security.scan_admission as admission
    import network_scanner.discovery.subnet_discoverer as subnet_module

    monkeypatch.setattr(subnet_module, "discover_subnet", _fake_sweep)
    FakeIntelRepo.instances = []
    monkeypatch.setattr(net_router, "IntelligenceRepository", FakeIntelRepo)
    monkeypatch.setattr(admission, "_control_plane_state", lambda: ([], None))
    monkeypatch.setattr(admission, "_ot_declared", lambda: False)
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)
    monkeypatch.setattr(admission, "_authorized_network_scope",
                        lambda: ["10.0.0.0/30"])

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield db_session

    app.dependency_overrides[get_db_session] = _session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/network/discover",
            json={"cidr": "10.0.0.0/30", "ports": [443], "scan": False},
        )
    assert response.status_code == 200
    assert "registration" not in response.json()
    assert FakeIntelRepo.instances == []  # repository never constructed
