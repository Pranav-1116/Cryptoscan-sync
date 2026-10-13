"""§4.5 (round 43) API surface: graph edges disclose their provenance.

GET /graph edges carry the engine's provenance class (DECLARED for operator-
declared system dependencies, SCANNER_DERIVED for evidence-chained inventory
links) alongside the existing evidence refs; blast radius accounts for the
classes of edges the traversal followed; GraphML/GEXF exports keep the
provenance attribute so external tools see the same honesty.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.crypto_asset import CryptoAsset
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency


@pytest.fixture()
def app_db():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "graph-provenance-" + "z" * 19)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    yield app, session
    engine.dispose()


def _seed(session):
    session.add_all([
        System(id="sys-core", name="core-bank"),
        System(id="sys-billing", name="billing"),
        System(id="sys-checkout", name="checkout"),
    ])
    session.flush()
    session.add(SystemDependency(parent_id="sys-core", child_id="sys-billing", relation="CALLS"))
    session.add(SystemDependency(parent_id="sys-billing", child_id="sys-checkout", relation="CALLS"))
    session.add(CryptoAsset(id="ca-rsa", algorithm="RSA-2048", file_path="src/Pay.java", line_number=1))
    session.add(SystemAsset(system_id="sys-core", asset_id="ca-rsa"))
    session.commit()


@pytest.mark.asyncio
async def test_graph_edges_carry_provenance_class_and_source(app_db):
    app, session = app_db
    _seed(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/graph")
    assert r.status_code == 200
    edges = r.json().get("edges") or []
    by_label = {}
    for e in edges:
        by_label.setdefault(e["label"], []).append(e)

    # operator-declared dependency: a declaration, not an observed call
    calls = by_label["CALLS"]
    assert calls, "seeded system dependencies must appear"
    for e in calls:
        assert e["provenance"] == "DECLARED"
        assert e["source"] == "system_dependencies (operator-declared)"

    # evidence-chained inventory link
    uses = by_label["USES"]
    assert uses
    for e in uses:
        assert e["provenance"] == "SCANNER_DERIVED"
        assert "evidence-chained" in e["source"]


@pytest.mark.asyncio
async def test_blast_radius_reports_provenance_of_followed_edges(app_db):
    app, session = app_db
    _seed(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/graph/blast-radius", params={"system_id": "sys-core", "hops": 3})
    assert r.status_code == 200
    body = r.json()
    assert {s["id"] for s in body["systems"]} == {"sys-billing", "sys-checkout"}
    counts = body["provenance_counts"]
    assert counts["DECLARED"] == 2, "both followed edges are operator declarations"
    assert counts["OBSERVED"] == 0, "nothing on this path was observed at runtime"
    assert set(counts) == {"OBSERVED", "DECLARED", "SCANNER_DERIVED", "INFERRED", "UNATTRIBUTED"}


@pytest.mark.asyncio
async def test_graphml_and_gexf_exports_keep_provenance_attribute(app_db):
    app, session = app_db
    _seed(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        graphml = await c.get("/api/v1/graph/export", params={"format": "graphml"})
        gexf = await c.get("/api/v1/graph/export", params={"format": "gexf"})
    assert graphml.status_code == 200 and gexf.status_code == 200

    xml = graphml.text
    assert 'attr.name="provenance"' in xml
    assert ">DECLARED<" in xml, "declared system dependencies must be labeled in the export"
    assert ">SCANNER_DERIVED<" in xml, "evidence-derived USES edges must be labeled too"

    gx = gexf.text
    assert 'id="provenance"' in gx
    assert 'value="DECLARED"' in gx
    assert 'value="SCANNER_DERIVED"' in gx


@pytest.mark.asyncio
async def test_graph_with_no_data_is_honestly_empty_not_fabricated(app_db):
    app, _session = app_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/graph")
    assert r.status_code == 200
    assert r.json()["edges"] == []
