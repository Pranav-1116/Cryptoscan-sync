"""Migration simulation against the live estate graph — the Meridian sandbox path.

Two Cryptava agents (the real agent package, on the fake host) push signed observations,
exactly as the sandbox's seven bank servers do. The Simulation workspace's migration panel
reads that estate graph, so what must hold:

* the systems the agents declared (bank-approved mapping) are the systems of the answer;
* a certificate, endpoint or library observed on a host lands in that host's system —
  the answer is never NOT_DETERMINED while the estate holds the algorithm;
* the declared CMDB dependency (SWIFT Gateway → Core Banking) and the observed outbound
  connection to the other host's IP both become connected systems;
* the deployed OpenSSL 3.0 is reported as not implementing ML-KEM, from its own capability
  evidence, and its vendor's release as not PQC-ready;
* the server a system runs on is listed as its platform and never invents a hardware
  blocker;
* nothing is written.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

CRYPTAVA = Path(__file__).resolve().parents[3] / "cryptava"
sys.path.insert(0, str(CRYPTAVA))
sys.path.insert(0, str(CRYPTAVA / "tests"))

import fakehost  # noqa: E402
from cryptava import agent as cryptava_agent  # noqa: E402
from cryptava.config import State, load_config  # noqa: E402
from cryptava.transport import TransportError  # noqa: E402


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/mig.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.delenv("CRYPTOSCAN_COLLECTOR_TRUST_KEYS", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_REQUIRE_SIGNED_OBSERVATIONS", raising=False)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.events.bus import reset_event_bus

    reset_event_bus()
    from api.main import create_app
    from api.routers import estate_graph as estate_router
    from fastapi.testclient import TestClient

    estate_router._ESTATE_TWIN_CACHE.clear()
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture()
def bank(client, monkeypatch, tmp_path):
    """Two Meridian servers with their agents: SWIFT Gateway and Core Banking."""

    def post(self, path, body, *, api_key=None, headers=None):
        sent = {"x-api-key": api_key or self.api_key} if (api_key or self.api_key) else {}
        sent.update(headers or {})
        response = client.post(path, json=body, headers=sent)
        if response.status_code >= 400:
            raise TransportError(f"{path}: HTTP {response.status_code}", status=response.status_code,
                                 body=response.json())
        return response.json()

    monkeypatch.setattr(cryptava_agent.Client, "post", post)
    token = client.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}

    def host(name, hostname, ip, system):
        config = load_config(env={})
        config.update(fakehost.build(tmp_path / name, hostname=hostname, ip=ip))
        config.update({"server": "http://testserver", "estate": "meridian-bank",
                       "tags": {"environment": "prod"}, "system": system})
        return config, State(tmp_path / name / "state")

    servers = [
        ("mrdn-sbx-dc1-swiftgw01", *host("a", "swiftgw01", "10.210.0.4", {
            "name": "SWIFT Gateway", "owner": "Payments Operations", "criticality": "tier-0",
            "depends_on": [{"name": "Core Banking", "via": "ISO 20022 over MQ"}]})),
        # the fake host's outbound peer is 10.210.0.11:1792 — the core banking server
        ("mrdn-sbx-dc1-coredb01", *host("b", "corebank01", "10.210.0.11", {
            "name": "Core Banking", "owner": "Core Banking Platform", "criticality": "tier-0"})),
    ]
    for name, cfg, state in servers:
        enrolled = client.post("/api/v1/control/agents/enroll", headers=h,
                               json={"name": name, "environment": "prod"}).json()
        cryptava_agent.enroll(cfg, state, agent_id=enrolled["agent_id"], token=enrolled["enrollment_token"])
        result = cryptava_agent.run_once(cfg, state)
        assert result["delivered"], result.get("error")
    return client, h


def test_context_lists_the_banks_systems_and_algorithms(bank):
    c, h = bank
    r = c.get("/api/v1/estate/evidence/simulation/migration/context", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    systems = {s["name"]: s for s in body["systems"]}
    assert {"SWIFT Gateway", "Core Banking"} <= set(systems)
    swift = systems["SWIFT Gateway"]
    assert swift["hosts"] == ["swiftgw01"]
    assert swift["certificates"] >= 1 and swift["libraries"] >= 1 and swift["servers"] == 1
    assert swift["criticality"] == "critical"
    algorithms = {a["algorithm"]: a for a in body["algorithms"]}
    assert "ECDSA" in algorithms and "SWIFT Gateway" in algorithms["ECDSA"]["systems"]
    deps = {(d["from"], d["to"]) for d in body["dependencies"]}
    assert ("SWIFT Gateway", "Core Banking") in deps


def test_ecdsa_to_mldsa_is_answered_from_the_estate(bank):
    c, h = bank
    before = c.get("/api/v1/estate/evidence/graph", headers=h).json()
    r = c.post("/api/v1/estate/evidence/simulation/migration", headers=h,
               json={"from_algo": "ECDSA", "to_algo": "ML-DSA-65"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source"] == "ESTATE_GRAPH" and body["mutates_nothing"] is True
    mig = body["migration"]
    assert mig["strategy"]["recommended"] != "NOT_DETERMINED", mig["headline"]
    assert mig["twin_context"]["kind"] == "ESTATE_GRAPH"
    systems = {s["name"]: s for s in mig["systems"]}
    assert "SWIFT Gateway" in systems
    swift = systems["SWIFT Gateway"]
    # a certificate this system serves carries ECDSA; its server is its platform, not a blocker
    assert swift["twin"]["certificates"], swift["twin"]
    assert swift["twin"]["platform"] and swift["twin"]["platform"][0]["manufacturer"]
    assert not any(f["code"] == "HARDWARE_CANNOT_RUN_TARGET" for f in swift["findings"])
    # the deployed OpenSSL 3.0 does not implement ML-DSA, from its own capability evidence
    libs = {lib["name"]: lib for lib in swift["twin"]["software"]["libraries"]}
    openssl = next(lib for name, lib in libs.items() if name.startswith("OpenSSL"))
    assert openssl["target_support"] == "NOT_SUPPORTED"
    codes = {f["code"] for f in swift["findings"]}
    assert "LIBRARY_LACKS_TARGET" in codes
    assert "VENDOR_RELEASE_NOT_READY" in codes
    # the CMDB-declared dependency on Core Banking is a connected system
    peers = {p["name"] for p in swift["twin"]["connections"]}
    assert "Core Banking" in peers
    assert mig["twin_context"]["servers"] >= 1 and mig["twin_context"]["vendors"] >= 1
    # read-only: the estate graph is unchanged
    after = c.get("/api/v1/estate/evidence/graph", headers=h).json()
    assert before.get("projection_id") == after.get("projection_id")


def test_scope_by_system_name_and_unknown_system(bank):
    c, h = bank
    r = c.post("/api/v1/estate/evidence/simulation/migration", headers=h,
               json={"from_algo": "ECDSA", "to_algo": "ML-DSA-65", "systems": ["Core Banking", "Nope"]})
    assert r.status_code == 200, r.text
    mig = r.json()["migration"]
    assert {s["name"] for s in mig["systems"]} <= {"Core Banking"}
    assert any("Nope" in u for u in mig["unknowns"])


def test_no_estate_is_a_404_not_an_empty_answer(client):
    token = client.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    r = client.post("/api/v1/estate/evidence/simulation/migration",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"from_algo": "RSA", "to_algo": "ML-KEM-768"})
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "no_estate_discovery"
