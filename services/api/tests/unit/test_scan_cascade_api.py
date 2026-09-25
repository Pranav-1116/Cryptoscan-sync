"""GET /scans/{id}/cascade — the dependency & cascade report persisted in Scan.statistics."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.scan import Scan

CASCADE = {
    "files_in_graph": 4, "edges": 3,
    "summary": {"providers": 2, "systems": 2, "weak_parameters": 1},
    "providers": [
        {"file": "core/CryptoUtil.java", "algorithms": ["AES"], "findings": 1, "direct_dependents": 2, "transitive_dependents": 3, "wave": 1, "rank": 1},
        {"file": "cards/CardSigner.java", "algorithms": ["RSA"], "findings": 1, "direct_dependents": 0, "transitive_dependents": 0, "wave": 2, "rank": 2},
    ],
    "libraries": [{"library": "BouncyCastle", "versions": ["1.78"], "files_using": 0, "declared_but_unused": True}],
    "shared_keys": [], "weak_parameters": [{"file": "cards/CardSigner.java", "line": 5, "algorithm": "RSA", "key_size": 1024, "minimum": 2048}],
    "migration_waves": [{"wave": 1, "why": "shared", "providers": ["core/CryptoUtil.java"], "dependents_affected": 3}],
    "systems": [{"system": "CORE", "paths": ["core/"], "providers": 1, "dependent_systems": ["CARDS"]}, {"system": "CARDS", "paths": ["cards/**"], "providers": 1, "depends_on_systems": ["CORE"]}],
}


def _app():
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(Scan(id="scan-1", scan_start=datetime(2026, 9, 25, tzinfo=timezone.utc), target_location="https://git/core.git", target_type="GIT_REPOSITORY", status="COMPLETED", statistics={"total_findings": 2, "cascade": CASCADE}))
    session.add(Scan(id="scan-old", scan_start=datetime(2026, 9, 25, tzinfo=timezone.utc), target_location="https://git/old.git", target_type="GIT_REPOSITORY", status="COMPLETED", statistics={"total_findings": 2}))
    session.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app


@pytest.mark.asyncio
async def test_cascade_endpoint_sections_and_system_filter():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/scans/scan-1/cascade")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["summary"]["providers"] == 2 and len(body["providers"]) == 2 and body["migration_waves"][0]["wave"] == 1
        r = await c.get("/api/v1/scans/scan-1/cascade", params={"section": "weak_parameters"})
        assert r.json()["total"] == 1 and r.json()["weak_parameters"][0]["key_size"] == 1024
        r = await c.get("/api/v1/scans/scan-1/cascade", params={"system": "CARDS"})
        assert [p["file"] for p in r.json()["providers"]] == ["cards/CardSigner.java"] and r.json()["systems"][0]["system"] == "CARDS"
        assert (await c.get("/api/v1/scans/scan-1/cascade", params={"system": "NOPE"})).status_code == 404
        assert (await c.get("/api/v1/scans/scan-1/cascade", params={"section": "bogus"})).status_code == 400
        assert (await c.get("/api/v1/scans/scan-old/cascade")).status_code == 404
        assert (await c.get("/api/v1/scans/missing/cascade")).status_code == 404


@pytest.mark.asyncio
async def test_scan_detail_carries_only_the_cascade_summary():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/scans/scan-1")
        stats = r.json()["statistics"]
        assert "cascade" not in stats and stats["cascade_summary"]["providers"] == 2 and stats["total_findings"] == 2


@pytest.mark.asyncio
async def test_code_cascade_rollup_joins_the_system_graph(monkeypatch):
    """CMDB system CORE gets code_cascade; code-only system CARDS is added; IMPORTS edge feeds blast radius."""
    from db.models.system import System
    from api import graph_builder
    from graph_engine.core import facade

    monkeypatch.setattr(graph_builder, "resolve_graph", lambda payload, **kw: facade.memory_graph(**payload))
    app = _app()
    session = next(app.dependency_overrides[get_db_session]())
    session.add(System(id="sys-core", name="CORE", owner="platform@bank", environment="prod", compliance_scopes=["PCI-DSS"]))
    session.commit()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/graph")
        assert r.status_code == 200, r.text
        nodes = {n["id"]: n for n in r.json()["nodes"]}
        assert nodes["system:sys-core"]["code_cascade"]["providers"] == 1 and nodes["system:sys-core"]["code_cascade"]["scan_id"] == "scan-1"
        assert nodes["system:CARDS"]["source"] == "cryptoscan-systems.yml" and nodes["system:CARDS"]["environment"] == "code"
        imports = [(e["from"], e["to"]) for e in r.json()["edges"] if e["label"] == "IMPORTS"]
        assert imports == [("system:CARDS", "system:sys-core")]
        r = await c.get("/api/v1/graph/dependents", params={"system_id": "sys-core", "hops": 2})
        assert r.status_code == 200 and any(s["id"] == "CARDS" for s in r.json()["systems"]), r.text
        r = await c.get("/api/v1/graph/blast-radius", params={"system_id": "CARDS", "hops": 2})
        assert [s["id"] for s in r.json()["systems"]] == ["sys-core"]
