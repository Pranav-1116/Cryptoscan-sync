"""Cryptava live performance → Performance Intelligence, end to end against the API app.

The agent's own sampler reads the fake host's kernel counters, signs the sample with
the key it registered at activation, and posts it with its machine key. What must hold:

* the machine key issued at activation reaches the route (no re-enrolment);
* only a sample signed by *this* agent's registered key is stored; a tampered,
  unsigned or foreign sample is refused;
* the figures land as Performance Intelligence metrics of the host's live-estate
  node — the overview, infrastructure and cryptography views and Collector Health
  read them — with units from the taxonomy and missing figures stored as unknown;
* ``/performance/live-systems`` shows one live card per server with its newest figures.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

CRYPTAVA = Path(__file__).resolve().parents[3] / "cryptava"
sys.path.insert(0, str(CRYPTAVA))
sys.path.insert(0, str(CRYPTAVA / "tests"))

import fakehost  # noqa: E402
from cryptava import agent as cryptava_agent  # noqa: E402
from cryptava.config import State, load_config  # noqa: E402
from cryptava.performance import Sampler, signed_sample  # noqa: E402
from cryptava.signing import SigningKey  # noqa: E402
from cryptava.transport import TransportError  # noqa: E402

PATH = "/api/v1/control/agents/heartbeat/performance"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/cvp.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.delenv("CRYPTAVA_PERFORMANCE_TENANT", raising=False)
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


class Clock:
    def __init__(self, base):
        self.base, self.now, self.tick = base, 1000.0, 1
        fakehost.performance_counters(base, 1)

    def __call__(self):
        return self.now

    def sleep(self, _):
        self.now += 60
        self.tick += 1
        fakehost.performance_counters(self.base, self.tick)


def _agent(c, h, tmp_path, name, hostname="swiftgw01", ip="10.210.0.4"):
    config = load_config(env={})
    config.update(fakehost.build(tmp_path / name, hostname=hostname, ip=ip))
    config.update({"server": "http://testserver", "estate": "meridian", "performance_scope": "host",
                   "fqdn": f"{hostname}.mrdn.bank", "system": {"name": "SWIFT Gateway"}})
    state = State(tmp_path / name / "state")
    enrolled = c.post("/api/v1/control/agents/enroll", headers=h, json={"name": name}).json()
    cryptava_agent.enroll(config, state, agent_id=enrolled["agent_id"], token=enrolled["enrollment_token"])
    clock = Clock(tmp_path / name)
    tls = lambda a, p, t: ({"ms": 4.2, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"}  # noqa: E731
                           if p == 8443 else None)
    sampler = Sampler(config, cryptava_agent.host_view(config), tls_probe=tls, clock=clock, sleep=clock.sleep)
    return config, state, sampler


def _window():
    now = datetime.now(timezone.utc)
    return {"tenant_id": "default", "window_start": (now - timedelta(minutes=30)).isoformat(),
            "window_end": (now + timedelta(seconds=5)).isoformat()}


def test_signed_samples_become_performance_intelligence(route_agent, tmp_path):
    c = route_agent
    h = _admin(c)
    config, state, sampler = _agent(c, h, tmp_path, "mrdn-prod-dc1-swiftgw01")

    result = cryptava_agent.send_performance(config, state, sampler)
    assert result["delivered"], result.get("error")
    assert result["authenticity"] == "VALID"
    assert result["accepted"] == result["metrics"] >= 15 and result["rejected"] == 0
    assert result["asset_id"] == "mrdn-prod-dc1-swiftgw01::host"
    assert state.last_performance_path.exists()

    # the Performance Intelligence views read the agent's figures
    overview = c.get("/api/v1/performance/overview", headers=h, params=_window())
    assert overview.status_code == 200, overview.text
    body = overview.json()
    assert body["cpu_utilization_pct"]["value"] == 25.0 and body["cpu_utilization_pct"]["state"] == "known"
    assert body["network_throughput_mbps"]["value"] == 1.0
    infra = c.get("/api/v1/performance/infrastructure/workspace", headers=h, params=_window()).json()
    row = next(r for r in infra["inventory"] if r["asset_id"] == "mrdn-prod-dc1-swiftgw01::host")
    assert row["cpu_pct"] == 25.0 and row["load"] == 0.42
    crypto = c.get("/api/v1/performance/cryptography", headers=h, params=_window()).json()
    assert crypto["tls_handshake_ms"]["p50"] == 4.2
    assert "TLS_AES_256_GCM_SHA384" in crypto["categories"]["algorithms"]["metrics"]
    health = c.get("/api/v1/performance/health", headers=h, params={"tenant_id": "default"}).json()
    collector = next(x for x in health["collectors"] if x["collector_id"] == "cryptava:mrdn-prod-dc1-swiftgw01")
    assert collector["status"] == "ok" and "signature verified" in collector["detail"]

    # the Live systems card
    live = c.get("/api/v1/performance/live-systems", headers=h).json()
    assert live["tenant_id"] == "default" and live["counts"]["live"] == 1
    card = live["systems"][0]
    assert card["agent"] == "mrdn-prod-dc1-swiftgw01" and card["state"] == "live" and card["signed"]
    assert card["host"] == "swiftgw01.mrdn.bank" and card["system"] == "SWIFT Gateway" and card["scope"] == "host"
    assert card["metrics"]["cpu.utilization_pct"]["value"] == 25.0
    assert card["metrics"]["cpu.utilization_pct"]["unit"] == "percent"     # from the taxonomy
    assert card["tls"] == [{"port": "8443", "ms": 4.2, "tls_version": "TLSv1.3",
                            "algorithm": "TLS_AES_256_GCM_SHA384"}]
    assert card["trend"]["cpu.utilization_pct"][0]["v"] == 25.0


def test_only_this_agents_signature_is_accepted(route_agent, tmp_path):
    c = route_agent
    h = _admin(c)
    config, state, sampler = _agent(c, h, tmp_path, "mrdn-prod-dc1-swiftgw01")
    _, other_state, _ = _agent(c, h, tmp_path, "mrdn-prod-dc1-core01", hostname="core01", ip="10.210.0.7")
    identity = state.identity()
    key = SigningKey.load(state.key_path)
    agent_key = {"x-api-key": identity["api_key"]}
    sample = sampler.sample()

    tampered = signed_sample(sample, identity, config, key)
    tampered["metrics"][0]["value"] = 1.0
    r = c.post(PATH, json=tampered, headers=agent_key)
    assert r.status_code == 422 and r.json()["detail"]["error"] == "signature_not_valid"

    unsigned = signed_sample(sample, identity, config, None)
    r = c.post(PATH, json=unsigned, headers=agent_key)
    assert r.status_code == 422 and r.json()["detail"]["error"] == "unsigned_sample"

    foreign = signed_sample(sample, identity, config, SigningKey.generate())
    r = c.post(PATH, json=foreign, headers=agent_key)
    assert r.status_code == 422 and r.json()["detail"]["error"] == "signature_not_valid"

    # another agent's machine key cannot speak for this agent
    r = c.post(PATH, json=signed_sample(sample, identity, config, key),
               headers={"x-api-key": other_state.identity()["api_key"]})
    assert r.status_code == 403

    future = dict(sample, observed_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    r = c.post(PATH, json=signed_sample(future, identity, config, key), headers=agent_key)
    assert r.status_code == 422 and r.json()["detail"]["error"] == "clock_ahead"

    ok = c.post(PATH, json=signed_sample(sample, identity, config, key), headers=agent_key)
    assert ok.status_code == 202, ok.text
    again = c.post(PATH, json=signed_sample(sample, identity, config, key), headers=agent_key)
    assert again.json()["accepted"] == 0 and again.json()["duplicate"] == ok.json()["accepted"]


def test_missing_figures_are_unknown_and_unknown_names_are_refused(route_agent, tmp_path):
    c = route_agent
    h = _admin(c)
    config, state, sampler = _agent(c, h, tmp_path, "mrdn-prod-dc1-swiftgw01")
    identity = state.identity()
    key = SigningKey.load(state.key_path)
    sample = sampler.sample()
    sample["metrics"] = [
        {"name": "cpu.utilization_pct", "quality": "missing", "reason": "/proc/stat is not readable",
         "labels": {"scope": "host"}},
        {"name": "made.up_metric", "value": 1, "labels": {}},
        {"name": "ram.utilization_pct", "value": 40.0, "labels": {"scope": "host", "agent": "spoofed"}},
    ]
    r = c.post(PATH, json=signed_sample(sample, identity, config, key), headers={"x-api-key": identity["api_key"]})
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 2 and r.json()["rejected"] == 1
    assert r.json()["refused"][0]["metric"] == "made.up_metric"

    overview = c.get("/api/v1/performance/overview", headers=h, params=_window()).json()
    assert overview["cpu_utilization_pct"]["value"] is None          # unknown — never a zero
    assert overview["memory_utilization_pct"]["value"] == 40.0
    card = c.get("/api/v1/performance/live-systems", headers=h).json()["systems"][0]
    assert card["missing"] == [{"metric": "cpu.utilization_pct", "reason": "/proc/stat is not readable"}]
    assert "cpu.utilization_pct" not in card["metrics"]
    samples = c.get("/api/v1/performance/samples", headers=h,
                    params={**_window(), "metric_name": "ram.utilization_pct"}).json()
    labels = samples["samples"][0]["labels"]
    assert labels["agent"] == "mrdn-prod-dc1-swiftgw01"               # the server sets who reported


def test_an_enrolled_agent_without_samples_is_a_named_gap(route_agent, tmp_path):
    c = route_agent
    h = _admin(c)
    _agent(c, h, tmp_path, "mrdn-prod-dc1-swiftgw01")
    live = c.get("/api/v1/performance/live-systems", headers=h).json()
    assert live["counts"] == {"systems": 1, "live": 0, "stale": 0, "no_samples": 1}
    assert live["systems"][0]["state"] == "no_samples" and live["systems"][0]["metrics"] == {}
