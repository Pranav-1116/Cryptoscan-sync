"""Cryptava end to end against the real API app.

The agent package (``services/cryptava``) is driven through its own code paths —
``enroll`` → ``run_once`` — with its HTTP client routed into the FastAPI TestClient, on a
fake host (``services/cryptava/tests/fakehost.py``). What must hold:

* names are unique and validated at enrolment; the one-time token works once;
* the agent's own key signs, and the platform verifies it against the key it
  registered at activation (``VALID`` with no deployment-wide trust variable);
* the agent's machine key can only speak for that agent (observations + heartbeat);
* two agents compose into one estate instead of overwriting each other, every edge
  resolves, and all six BOMs are populated from what the agents read.
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

BOMS = ("SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM")


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/cv.db")
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
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


@pytest.fixture()
def route_agent(client, monkeypatch):
    """Send the agent's HTTP calls into the TestClient instead of the network."""

    def post(self, path, body, *, api_key=None, headers=None):
        sent = {"x-api-key": api_key or self.api_key} if (api_key or self.api_key) else {}
        sent.update(headers or {})
        response = client.post(path, json=body, headers=sent)
        if response.status_code >= 400:
            payload = response.json()
            raise TransportError(f"{path}: HTTP {response.status_code} — {payload}",
                                 status=response.status_code, body=payload)
        return response.json()

    monkeypatch.setattr(cryptava_agent.Client, "post", post)
    return client


def _admin(c):
    token = c.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def _enrol(c, h, name):
    r = c.post("/api/v1/control/agents/enroll", headers=h, json={"name": name, "environment": "prod"})
    assert r.status_code == 201, r.text
    return r.json()


def _host(tmp_path, name, hostname, ip, system=None):
    config = load_config(env={})
    config.update(fakehost.build(tmp_path / name, hostname=hostname, ip=ip))
    config.update({"server": "http://testserver", "estate": "meridian", "tags": {"environment": "prod"},
                   "system": system})
    return config, State(tmp_path / name / "state")


# --------------------------------------------------------------------------- #
# enrolment
# --------------------------------------------------------------------------- #

def test_names_are_unique_and_validated(client):
    h = _admin(client)
    _enrol(client, h, "mrdn-prod-dc1-swiftgw01")
    dup = client.post("/api/v1/control/agents/enroll", headers=h, json={"name": "MRDN-prod-dc1-swiftgw01"})
    assert dup.status_code == 409
    assert dup.json()["detail"]["error"] == "agent_name_taken"
    bad = client.post("/api/v1/control/agents/enroll", headers=h, json={"name": "swift gw 01"})
    assert bad.status_code == 422
    assert bad.json()["detail"]["error"] == "agent_name_invalid"


def test_activation_token_is_one_time_and_key_is_checked(client):
    h = _admin(client)
    enrolled = _enrol(client, h, "mrdn-prod-dc1-core01")
    from cryptava.signing import SigningKey

    key = SigningKey.generate()
    body = {"agent_id": enrolled["agent_id"], "enrollment_token": enrolled["enrollment_token"],
            "public_key": key.public_b64}
    wrong = client.post("/api/v1/control/agents/activate", json={**body, "enrollment_token": "x" * 40})
    assert wrong.status_code == 403
    bad_key = client.post("/api/v1/control/agents/activate", json={**body, "public_key": "A" * 44})
    assert bad_key.status_code == 422
    ok = client.post("/api/v1/control/agents/activate", json=body)
    assert ok.status_code == 201, ok.text
    issued = ok.json()
    assert issued["name"] == "mrdn-prod-dc1-core01" and issued["contributor"] == "mrdn-prod-dc1-core01"
    assert issued["key_id"] == key.key_id
    assert set(issued["scopes"]) == {"/ingestion/observations", "/control/agents/heartbeat"}
    reuse = client.post("/api/v1/control/agents/activate", json=body)
    assert reuse.status_code == 403

    # the machine key reaches its two routes and nothing else
    agent_key = {"x-api-key": issued["api_key"]}
    assert client.get("/api/v1/control/agents", headers=agent_key).status_code in (401, 403)
    beat = client.post("/api/v1/control/agents/heartbeat", headers=agent_key,
                       json={"agent_id": issued["agent_id"], "version": "1.0.0"})
    assert beat.status_code == 200, beat.text


# --------------------------------------------------------------------------- #
# the agent itself
# --------------------------------------------------------------------------- #

def test_two_agents_compose_all_six_boms(route_agent, tmp_path):
    c = route_agent
    h = _admin(c)
    swift_cfg, swift_state = _host(tmp_path, "a", "swiftgw01", "10.210.0.4", system={
        "name": "SWIFT Gateway", "owner": "Payments Ops",
        "applications": [{"name": "Alliance Access", "services": ["nginx"]}]})
    core_cfg, core_state = _host(tmp_path, "b", "corebank01", "10.210.0.9")

    for name, cfg, state in (("mrdn-prod-dc1-swiftgw01", swift_cfg, swift_state),
                             ("mrdn-prod-dc1-corebank01", core_cfg, core_state)):
        enrolled = _enrol(c, h, name)
        identity = cryptava_agent.enroll(cfg, state, agent_id=enrolled["agent_id"],
                                         token=enrolled["enrollment_token"])
        assert identity["name"] == name and "api_key" not in identity
        assert (state.key_path.stat().st_mode & 0o777) == 0o600
        assert (state.identity_path.stat().st_mode & 0o777) == 0o600

    first = cryptava_agent.run_once(swift_cfg, swift_state)
    assert first["delivered"], first.get("error")
    assert first["heartbeat"] == "ok"
    assert first["response"]["authenticity"] == "VALID"
    assert first["response"]["signed_by_agent"]["name"] == "mrdn-prod-dc1-swiftgw01"

    second = cryptava_agent.run_once(core_cfg, core_state)
    assert second["delivered"], second.get("error")
    contribution = second["response"]["contribution"]
    assert sorted(contribution["contributors"]) == ["mrdn-prod-dc1-corebank01", "mrdn-prod-dc1-swiftgw01"]

    listed = c.get("/api/v1/ingestion/contributors", headers=h, params={"estate": "meridian"})
    assert listed.status_code == 200, listed.text
    rows = {row["contributor"]: row for row in listed.json()["contributors"]}
    names = set(rows)
    assert rows["mrdn-prod-dc1-swiftgw01"]["authenticity"] == "VALID"
    assert {p["plane"].split(" ")[0] for p in rows["mrdn-prod-dc1-swiftgw01"]["planes"]} == {
        "HBOM", "SBOM", "NBOM", "CBOM", "VBOM", "TechBOM"}
    assert {"mrdn-prod-dc1-swiftgw01", "mrdn-prod-dc1-corebank01"} <= set(names)

    # a fresh, unchanged run from the first agent must not erase the second agent's hosts
    third = cryptava_agent.run_once(swift_cfg, swift_state)
    assert third["delivered"], third.get("error")

    # the composed estate, as the console reads it: all six BOMs populated from both hosts
    stored = c.get("/api/v1/estate/evidence/boms", headers=h)
    assert stored.status_code == 200, stored.text
    boms = stored.json()["boms"]
    for kind in BOMS:
        assert boms[kind]["components"], f"{kind} is empty"
    hosts = {comp["name"] for comp in boms["HBOM"]["components"] if comp.get("type") == "HOST"}
    assert {"swiftgw01", "corebank01"} <= hosts, hosts
    systems = {comp["name"] for comp in boms["TECHBOM"]["components"] if comp.get("type") == "SYSTEM"}
    assert "SWIFT Gateway" in systems
    cbom_text = str(boms["CBOM"])
    assert "OpenSSL" in cbom_text or "openssl" in cbom_text.lower()
    assert "swiftgw01.mrdn.bank" in cbom_text  # the CA-issued certificate on disk
    assert boms["VBOM"].get("declared_capabilities")

    # every edge the agents sent was accepted — none fell into "unresolved"
    graph = c.get("/api/v1/estate/evidence/graph", headers=h)
    assert graph.status_code == 200, graph.text
    unresolved = graph.json()["unresolved_edges"]
    assert len(graph.json()["edges"]) > 50
    assert unresolved == [], unresolved[:3]


def test_agent_key_cannot_speak_for_another_agent(route_agent, tmp_path):
    c = route_agent
    h = _admin(c)
    cfg_a, state_a = _host(tmp_path, "a", "swiftgw01", "10.210.0.4")
    cfg_b, state_b = _host(tmp_path, "b", "corebank01", "10.210.0.9")
    ids = {}
    for name, cfg, state in (("agent-a", cfg_a, state_a), ("agent-b", cfg_b, state_b)):
        enrolled = _enrol(c, h, name)
        ids[name] = cryptava_agent.enroll(cfg, state, agent_id=enrolled["agent_id"],
                                          token=enrolled["enrollment_token"])["agent_id"]
    key_a = {"x-api-key": state_a.identity()["api_key"]}

    payload = cryptava_agent.build_payload(cryptava_agent.collect(cfg_a), cfg_a, contributor="agent-b", key=None)
    spoof = c.post("/api/v1/ingestion/observations", headers=key_a, json=payload)
    assert spoof.status_code == 403
    assert spoof.json()["detail"]["error"] == "contributor_mismatch"

    beat = c.post("/api/v1/control/agents/heartbeat", headers=key_a, json={"agent_id": ids["agent-b"]})
    assert beat.status_code == 403

    # retiring an agent revokes its machine key
    retired = c.post(f"/api/v1/control/agents/{ids['agent-a']}/upgrade", headers=h, json={"action": "retire"})
    assert retired.status_code == 200, retired.text
    after = c.post("/api/v1/control/agents/heartbeat", headers=key_a, json={"agent_id": ids["agent-a"]})
    assert after.status_code in (401, 403)


def test_contributor_slice_can_be_removed(route_agent, tmp_path):
    c = route_agent
    h = _admin(c)
    cfg, state = _host(tmp_path, "a", "swiftgw01", "10.210.0.4")
    enrolled = _enrol(c, h, "mrdn-prod-dc1-swiftgw01")
    cryptava_agent.enroll(cfg, state, agent_id=enrolled["agent_id"], token=enrolled["enrollment_token"])
    assert cryptava_agent.run_once(cfg, state)["delivered"]
    removed = c.delete("/api/v1/ingestion/contributors/mrdn-prod-dc1-swiftgw01", headers=h,
                       params={"estate": "meridian"})
    assert removed.status_code == 200, removed.text
    assert "mrdn-prod-dc1-swiftgw01" not in removed.json()["contributors"]


def test_one_step_rollout_and_rebuilt_host_keep_the_name(route_agent, tmp_path):
    """Ansible/DaemonSet path: enrol + activate with a provisioning credential; re-running
    it on a rebuilt host (identity lost) re-issues a token instead of failing on the name."""
    c = route_agent
    h = _admin(c)
    bearer = h["Authorization"]
    cfg, state = _host(tmp_path, "a", "swiftgw01", "10.210.0.4")
    first = cryptava_agent.enroll(cfg, state, agent_id=None, token=None,
                                  name="mrdn-prod-dc1-swiftgw01", provision_key=bearer)
    old_key = state.identity()["api_key"]
    assert cryptava_agent.run_once(cfg, state)["delivered"]

    rebuilt = State(tmp_path / "rebuilt-state")
    second = cryptava_agent.enroll(cfg, rebuilt, agent_id=None, token=None,
                                   name="mrdn-prod-dc1-swiftgw01", provision_key=bearer)
    assert second["agent_id"] == first["agent_id"] and second["key_id"] != first["key_id"]
    agents = [a for a in c.get("/api/v1/control/agents", headers=h).json()["agents"]
              if a["name"] == "mrdn-prod-dc1-swiftgw01"]
    assert len(agents) == 1
    # the old host's machine key was revoked when the rebuilt host activated
    stale = c.post("/api/v1/control/agents/heartbeat", headers={"x-api-key": old_key},
                   json={"agent_id": first["agent_id"]})
    assert stale.status_code in (401, 403)
    assert cryptava_agent.run_once(cfg, rebuilt)["response"]["authenticity"] == "VALID"


def test_asset_register_completes_hbom_and_vbom_end_to_end(route_agent, tmp_path):
    """A host with no firmware tables + the bank's CMDB record: HBOM and VBOM complete,
    the console sees how each BOM was collected, and the contracts reach the VBOM."""
    import json
    import shutil

    c = route_agent
    h = _admin(c)
    cfg, state = _host(tmp_path, "c", "mobileapi01", "10.210.0.3", system={"name": "Mobile Banking API"})
    shutil.rmtree(Path(cfg["sys"]) / "class/dmi", ignore_errors=True)
    record = tmp_path / "asset-record.json"
    record.write_text(json.dumps({
        "source": "Meridian CMDB export",
        "hardware": {"manufacturer": "VMware, Inc.", "model": "VMware7,1", "serial_number": "VMware-42 1c 6d",
                     "asset_tag": "MRDN-VM-MOBAPI01"},
        "contracts": [
            {"vendor": "OpenSSL Software Foundation", "contract_id": "OSF-PS-2024-117",
             "support_level": "Premium Support", "end": "2099-03-31"},
            {"vendor": "Debian Project", "support_level": "community"},
        ],
    }))
    cfg["asset_record"] = str(record)
    enrolled = _enrol(c, h, "mrdn-sbx-dc1-mobileapi01")
    cryptava_agent.enroll(cfg, state, agent_id=enrolled["agent_id"], token=enrolled["enrollment_token"])
    run = cryptava_agent.run_once(cfg, state)
    assert run["delivered"], run.get("error")
    assert run["response"]["authenticity"] == "VALID"

    rows = {row["contributor"]: row for row in c.get("/api/v1/ingestion/contributors", headers=h).json()["contributors"]}
    planes = {p["plane"].split(" ")[0]: p for p in rows["mrdn-sbx-dc1-mobileapi01"]["planes"]}
    assert planes["HBOM"]["status"] == "COMPLETE", planes["HBOM"]["reason"]
    assert planes["VBOM"]["status"] == "COMPLETE", planes["VBOM"]["reason"]
    for key, plane in planes.items():
        assert plane["sources"], f"{key} has no sources"
    hbom_sources = {s["source"]: s["state"] for s in planes["HBOM"]["sources"]}
    assert hbom_sources["/sys/class/dmi/id"] == "ABSENT"
    assert hbom_sources[str(record)] == "READ"

    boms = c.get("/api/v1/estate/evidence/boms", headers=h).json()["boms"]
    contracts = boms["VBOM"].get("contracts") or []
    assert any(row["contract_id"] == "OSF-PS-2024-117" and row["contract_state"] == "ACTIVE" for row in contracts)
    assert all(row["register"] == "Meridian CMDB export" for row in contracts)
    graph = c.get("/api/v1/estate/evidence/graph", headers=h).json()
    assert graph["unresolved_edges"] == [], graph["unresolved_edges"][:3]
