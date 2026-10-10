"""Round 20 (reports 03/04/05/08/09/13/DISCOVERY): the silent-truncation
bug class (estate views capped at one 500/1000-row page) and graph export."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.graph_builder import collect_graph_payload
from api.main import create_app
from db.connection.session import Base
from db.models.system import System
from db.models.user import User

SECRET = "round20-test-secret-" + "x" * 16


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", SECRET)
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(User(username="op-user", roles="developer", password_hash="x"))
    session.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "op-user"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


# --------------------------------------------------------------------- #
# The bug: one 500-row page silently dropped the rest of the estate
# --------------------------------------------------------------------- #

def test_graph_payload_includes_all_pages_of_systems():
    """501 systems used to yield 500 in the graph payload (page 1 only)."""
    app, session, engine = _make_app()
    try:
        session.add_all(
            System(id=f"sys-{i:04d}", name=f"system-{i:04d}") for i in range(501)
        )
        session.commit()
        payload = collect_graph_payload(session)
        assert len(payload["systems"]) == 501  # every page, not just the first
        assert payload["collection"]["systems_total"] == 501
        assert payload["collection"]["systems_truncated"] is False
        names = {s["name"] for s in payload["systems"]}
        assert "system-0500" in names  # the row the old bug dropped
    finally:
        engine.dispose()


def test_list_all_bounded_reports_truncation():
    app, session, engine = _make_app()
    try:
        session.add_all(System(id=f"s{i}", name=f"n{i:03d}") for i in range(12))
        session.commit()
        repo = __import__("db.repositories.system_repository", fromlist=["SystemRepository"]).SystemRepository(session)
        rows, truncated = repo.list_all_bounded(page_size=5, max_rows=10)
        assert len(rows) == 10
        assert truncated is True
        rows, truncated = repo.list_all_bounded(page_size=5, max_rows=50)
        assert len(rows) == 12
        assert truncated is False
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_agility_pqc_sees_systems_beyond_the_old_cap():
    app, session, engine = _make_app()
    try:
        session.add_all(
            System(id=f"sys-{i:04d}", name=f"system-{i:04d}") for i in range(505)
        )
        session.commit()
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        resp = await client.get("/api/v1/agility/pqc")
        assert resp.status_code == 200
        data = resp.json()
        assert data["systems_truncated"] is False
        # the aggregate endpoint no longer under-counts: 505 systems seen
        assert len(data["systems"]) == 0  # none have evidence — honest empty
        # but the graph side must have all of them
        payload = collect_graph_payload(session)
        assert len(payload["systems"]) == 505
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_exposure_paths_bounds_report_truncation():
    app, session, engine = _make_app()
    try:
        session.add(System(id="sys-edge", name="edge", cloud_provider="AWS"))
        session.commit()
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        resp = await client.get("/api/v1/exposure/paths")
        assert resp.status_code == 200
        assert resp.json()["bounds"]["systems_truncated"] is False
    finally:
        engine.dispose()


# --------------------------------------------------------------------- #
# Report 09 rec #12 — graph export
# --------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_graph_export_graphml():
    app, session, engine = _make_app()
    try:
        from db.models.system_dependency import SystemDependency

        session.add(System(id="sys-a", name="alpha", cloud_provider="AWS"))
        session.add(System(id="sys-b", name="beta"))
        session.add(SystemDependency(parent_id="sys-a", child_id="sys-b", relation="depends-on"))
        session.commit()
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        resp = await client.get("/api/v1/graph/export?format=graphml")
        assert resp.status_code == 200
        assert "attachment" in resp.headers["content-disposition"]
        root = ET.fromstring(resp.text)
        assert root.tag.endswith("graphml")
        ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
        nodes = root.findall(".//g:node", ns)
        edges = root.findall(".//g:edge", ns)
        assert len(nodes) >= 2
        assert len(edges) >= 1  # system:alpha -> system:beta dependency edge
        edge_sources = {e.get("source") for e in edges}
        assert "system:sys-a" in edge_sources
        node_ids = {n.get("id") for n in nodes}
        assert "system:sys-a" in node_ids and "system:sys-b" in node_ids
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_graph_export_gexf():
    app, session, engine = _make_app()
    try:
        session.add(System(id="sys-a", name="alpha"))
        session.commit()
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        resp = await client.get("/api/v1/graph/export?format=gexf")
        assert resp.status_code == 200
        root = ET.fromstring(resp.text)
        assert root.tag.endswith("gexf")
        nodes = root.findall(".//{http://gexf.net/1.3}node")
        assert any(n.get("id") == "system:sys-a" for n in nodes)
        kinds = root.findall(".//{http://gexf.net/1.3}attvalue")
        assert any(k.get("value") == "System" for k in kinds)
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_graph_export_rejects_unknown_format():
    app, session, engine = _make_app()
    try:
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        resp = await client.get("/api/v1/graph/export?format=cypher")
        assert resp.status_code == 422
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_graph_export_escapes_xml_hostile_names():
    app, session, engine = _make_app()
    try:
        session.add(System(id="sys-x", name='alpha<script>&"'))
        session.commit()
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        resp = await client.get("/api/v1/graph/export")
        assert resp.status_code == 200
        ET.fromstring(resp.text)  # must parse: nothing injected
        assert "<script>" not in resp.text
    finally:
        engine.dispose()


# --------------------------------------------------------------------- #
# Round 21 (report 03): container scans reach the graph payload
# --------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_container_scans_in_graph_payload_with_honest_linkage():
    """ContainerImage nodes appear; system link only when the container
    scan's scan_id resolves to a Scan whose target matches a system."""
    from db.models.container_scan import ContainerScan
    from db.models.scan import Scan

    app, session, engine = _make_app()
    try:
        session.add(System(id="sys-web", name="web", scan_target="https://github.com/org/web.git"))
        session.add(Scan(id="scan-c1", scan_start=__import__("datetime").datetime(2026, 10, 10),
                         target_location="https://github.com/org/web.git",
                         target_type="GIT_REPOSITORY"))
        session.add(ContainerScan(id="cs-1", scan_id="scan-c1", target="nginx:1.25",
                                  package_count=10, library_count=4, vuln_count=2, result={}))
        session.add(ContainerScan(id="cs-2", scan_id=None, target="redis:7",
                                  package_count=3, library_count=1, vuln_count=0, result={}))
        session.commit()

        payload = collect_graph_payload(session)
        by_id = {c["id"]: c for c in payload["container_images"]}
        assert set(by_id) == {"cs-1", "cs-2"}
        assert by_id["cs-1"]["system_ids"] == ["sys-web"]   # linked via scan target
        assert by_id["cs-2"]["system_ids"] == []            # floating: no invented link
        assert by_id["cs-1"]["vuln_count"] == 2

        # the memory graph builds nodes + RUNS edges from the payload
        graph = __import__("graph_engine.core.facade", fromlist=["memory_graph"]).memory_graph(**payload)
        assert graph.nodes.get("container:cs-1", {}).get("kind") == "ContainerImage"
        assert ("container:cs-1", "RUNS") in graph.out["system:sys-web"]
        assert "container:cs-2" in graph.nodes
    finally:
        engine.dispose()
