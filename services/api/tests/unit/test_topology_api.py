"""Declared network topology (advanced/58 P0#1–2, round 31)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register all tables
from api.config.settings import get_settings
from db.topology import TopologyError, declared_chains_to_system, validate_topology_document


def _doc():
    return {
        "format": "zelnx-topology/v1",
        "nodes": [
            {"kind": "dns", "name": "api.bank.example", "attrs": {"record": "A"}},
            {"kind": "cdn", "name": "cdn-edge-1"},
            {"kind": "waf", "name": "waf-prod"},
            {"kind": "load_balancer", "name": "alb-public",
             "system_ids": ["sys-pay"], "system_relation": "TERMINATES_AT"},
        ],
        "edges": [
            {"from": "api.bank.example", "to": "cdn-edge-1", "relation": "RESOLVES_TO"},
            {"from": "cdn-edge-1", "to": "waf-prod", "relation": "PROXIES_TO"},
            {"from": "waf-prod", "to": "alb-public", "relation": "PROXIES_TO"},
        ],
    }


# ── pure validation ──────────────────────────────────────────────────


def test_validation_normalizes_and_rejects():
    doc = validate_topology_document(_doc())
    assert len(doc["nodes"]) == 4 and len(doc["edges"]) == 3
    assert all(n["source"] == "declared" for n in doc["nodes"])
    with pytest.raises(TopologyError):
        validate_topology_document({**_doc(), "nodes": [
            {"kind": "router", "name": "x"}]})  # unknown kind
    bad_edge = {**_doc(), "edges": [{"from": "ghost", "to": "waf-prod",
                                     "relation": "PROXIES_TO"}]}
    with pytest.raises(TopologyError):
        validate_topology_document(bad_edge)
    with pytest.raises(TopologyError):
        validate_topology_document({"nodes": []})
    with pytest.raises(TopologyError):
        validate_topology_document({"nodes": [{"kind": "dns", "name": "x"},
                                              {"kind": "dns", "name": "x"}]})


def test_cycles_rejected_and_chains_walked():
    cyclic = {
        "nodes": [{"kind": "cdn", "name": "a"}, {"kind": "cdn", "name": "b"},
                  {"kind": "load_balancer", "name": "lb", "system_ids": ["s"]}],
        "edges": [
            {"from": "a", "to": "b", "relation": "PROXIES_TO"},
            {"from": "b", "to": "a", "relation": "PROXIES_TO"},
            {"from": "b", "to": "lb", "relation": "PROXIES_TO"},
        ],
    }
    with pytest.raises(TopologyError, match="cycle"):
        validate_topology_document(cyclic)

    doc = validate_topology_document(_doc())
    chains = declared_chains_to_system(doc["nodes"], doc["edges"], "sys-pay")
    assert len(chains) == 1
    kinds = [step["node"]["kind"] for step in chains[0]]
    assert kinds == ["dns", "cdn", "waf", "load_balancer"]
    relations = [step["relation"] for step in chains[0]]
    assert relations == ["RESOLVES_TO", "PROXIES_TO", "PROXIES_TO", "TERMINATES_AT"]
    assert declared_chains_to_system(doc["nodes"], doc["edges"], "sys-other") == []


# ── API + graph + exposure integration ───────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/topology.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()

    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None

    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, db_url


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _seed_system(db_url, system_id="sys-pay", name="Payments"):
    eng = create_engine(db_url)
    Session = sessionmaker(bind=eng)
    session = Session()
    from db.models.system import System

    session.add(System(id=system_id, name=name, environment="PROD"))
    session.commit()
    session.close()
    eng.dispose()


def test_topology_lifecycle_and_graph(sqlite_app):
    client, db_url = sqlite_app
    _seed_system(db_url)

    # unauthenticated declaration rejected (before login primes cookies)
    r = client.post("/api/v1/network/topology", json={"document": _doc()})
    assert r.status_code == 401

    admin = _login(client)

    # invalid document → 422, nothing persisted
    r = client.post("/api/v1/network/topology",
                    json={"document": {"nodes": [{"kind": "bogus", "name": "x"}]}},
                    headers=admin)
    assert r.status_code == 422
    assert client.get("/api/v1/network/topology").json()["nodes"] == []

    # valid declaration
    r = client.post("/api/v1/network/topology", json={"document": _doc()}, headers=admin)
    assert r.status_code == 200, r.text
    assert r.json()["nodes"] == 4 and r.json()["edges"] == 3

    stored = client.get("/api/v1/network/topology").json()
    assert stored["source"] == "declared"
    assert {n["name"] for n in stored["nodes"]} >= {"waf-prod", "alb-public"}

    # chains to a system
    r = client.get("/api/v1/network/topology/paths", params={"system_id": "sys-pay"})
    assert r.status_code == 200
    body = r.json()
    assert body["chain_count"] == 1
    assert [step["kind"] for step in body["chains"][0]] == \
        ["dns", "cdn", "waf", "load_balancer"]
    assert client.get("/api/v1/network/topology/paths",
                      params={"system_id": "nope"}).json()["chain_count"] == 0

    # graph: declared nodes + edges + system links, provenance kept
    from api.graph_builder import collect_graph_payload
    from db.connection.session import SessionLocal

    session = SessionLocal()
    try:
        payload = collect_graph_payload(session)
    finally:
        session.close()
    assert len(payload["topology"]["nodes"]) == 4

    from graph_engine.core.facade import memory_graph

    graph = memory_graph(**payload)
    vis = graph.to_vis()
    node_kinds = {n.get("kind") for n in vis["nodes"]}
    assert {"DNSRecord", "CDN", "WAF", "LoadBalancer"} <= node_kinds
    edge_rels = {e.get("label") for e in vis["edges"]}
    assert {"RESOLVES_TO", "PROXIES_TO", "TERMINATES_AT"} <= edge_rels
    declared = [n for n in vis["nodes"] if n.get("kind") == "WAF"]
    assert declared and declared[0].get("declared_source") == "declared"

    # exposure: sys-pay becomes a declared entry candidate with the chain
    r = client.get("/api/v1/exposure/paths")
    assert r.status_code == 200
    entries = r.json()["entry_candidates"]
    pay = [e for e in entries if e["id"] == "sys-pay"]
    assert pay and "declared topology" in pay[0]["reason"]
    assert pay[0]["declared_chain_count"] == 1
    assert r.json()["declared_topology_entries"] == 1

    # re-declare is a full replace (idempotent shape, never stacked)
    r = client.post("/api/v1/network/topology", json={"document": _doc()}, headers=admin)
    assert r.status_code == 200
    stored2 = client.get("/api/v1/network/topology").json()
    assert len(stored2["nodes"]) == 4
