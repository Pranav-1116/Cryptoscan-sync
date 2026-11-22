"""Operations monitoring over the agent-fed estate.

The rules run first as pure functions, with their thresholds. Then the end-to-end path:
two real Cryptava agents on the fake host enrol, report and send a signed performance
sample, as the Meridian sandbox servers do. Each of the four views must answer from what
those agents sent:

* fleet: both agents LIVE, mapped to their declared systems, with their planes and sources;
* hosts: running services, the libraries they load, and the signed CPU sample;
* monitor: no agent alert while both report, and a tier-0 agent that goes silent is CRITICAL;
* activity: the agents' enrolment and the estate changes, newest first, attributed to agents.
"""

from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

from api import operations_monitor as ops

_SIM = Path(__file__).with_name("test_estate_migration_simulation.py")
_spec = importlib.util.spec_from_file_location("_estate_sim_fixtures", _SIM)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
client = _mod.client  # noqa: F811 — pytest fixtures reused from the migration simulation tests
bank = _mod.bank
fakehost = _mod.fakehost
cryptava_agent = _mod.cryptava_agent

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


def _agent(name, age, **extra):
    return {"id": f"id-{name}", "name": name, "status": "connected", "healthy": True, "link": "encrypted",
            "last_heartbeat_at": None if age is None else NOW - timedelta(seconds=age), **extra}


def _slice(system="SWIFT Gateway", criticality="tier-0", planes=(("CBOM · cryptography", "COMPLETE"),)):
    return {
        "assets": [{"ref": "host", "type": "HOST", "name": "swiftgw01",
                    "attributes": {"fqdn": "swiftgw01.mrdn.bank", "ip_addresses": ["10.210.0.4"]}},
                   {"ref": "system:x", "type": "SYSTEM", "name": system}],
        "evidence": [{"target": "system:x", "evidence_type": "CONFIGURED",
                      "facts": {"mapping": "host is part of this business system", "criticality": criticality,
                                "owner": "Payments Operations"}}],
        "relationships": [],
        "collectors": [{"plane": p, "status": st, "reason": "r",
                        "sources": [{"source": "/proc", "state": "READ", "found": 3}]} for p, st in planes],
        "meta": {"authenticity": "VALID", "received_at": NOW.isoformat()},
    }


def test_liveness_thresholds_are_the_heartbeat_and_the_estate_staleness():
    kw = {"heartbeat": 60, "stale_after": 600}
    assert ops.liveness(_agent("a", 30), NOW, **kw)["state"] == ops.LIVE
    assert ops.liveness(_agent("a", 181), NOW, **kw)["state"] == ops.LATE
    assert ops.liveness(_agent("a", 601), NOW, **kw)["state"] == ops.OFFLINE
    assert ops.liveness(_agent("a", None), NOW, **kw)["state"] == ops.NEVER
    assert ops.liveness(_agent("a", 9999, status="retired"), NOW, **kw)["state"] == ops.RETIRED


def test_a_silent_tier0_agent_is_critical_and_the_estate_is_degraded():
    view = ops.fleet([_agent("swiftgw01", 900), _agent("corebank01", 20)],
                     {"swiftgw01": _slice(), "corebank01": _slice("Core Banking", "tier-1")}, {}, NOW,
                     heartbeat=60, stale_after=600)
    rows = ops.alerts(view, connection={"state": "LIVE"}, coverage={"coverage_percent": 95}, changes=[], patterns=[])
    offline = [a for a in rows if a["rule"] == "AGENT_OFFLINE"]
    assert len(offline) == 1 and offline[0]["severity"] == "CRITICAL" and offline[0]["system"] == "SWIFT Gateway"
    # it went silent at the threshold, not when it was last heard from
    assert offline[0]["since"] == (NOW - timedelta(seconds=300)).isoformat()
    assert ops.overall(view, rows)["state"] == "DEGRADED"


def test_failed_plane_delivery_and_resources_raise_their_rules():
    agent = _agent("swiftgw01", 10, healthy=False, offline_events_buffered=2)
    slice_ = _slice(planes=(("NBOM · network", "FAILED"), ("VBOM · vendors", "UNKNOWN")))
    perf = {"swiftgw01": ops.performance_summary(
        [{"metric_name": "cpu.utilization_pct", "value": 97.0, "unit": "%", "observed_at": NOW}], NOW, heartbeat=60)}
    view = ops.fleet([agent], {"swiftgw01": slice_}, perf, NOW, heartbeat=60, stale_after=600)
    rules = {a["rule"]: a["severity"] for a in ops.alerts(view, connection=None, coverage={"coverage_percent": 60},
                                                         changes=[], patterns=[])}
    assert rules["DELIVERY_FAILING"] == "HIGH" and rules["DELIVERY_BUFFERED"] == "MEDIUM"
    assert rules["PLANE_FAILED"] == "HIGH" and rules["PLANE_UNKNOWN"] == "LOW"
    assert rules["HOST_CPU_HIGH"] == "MEDIUM" and rules["COVERAGE_LOW"] == "MEDIUM"


def test_no_agents_is_not_connected_and_no_sample_is_not_idle():
    view = ops.fleet([], {}, {}, NOW, heartbeat=60, stale_after=600)
    assert ops.overall(view, [])["state"] == "NOT_CONNECTED"
    assert ops.performance_summary([], NOW, heartbeat=60)["state"] == "NOT_SAMPLED"


def test_activity_is_one_timeline_attributed_to_agents():
    view = ops.fleet([_agent("mrdn-swiftgw01", 10)], {"mrdn-swiftgw01": _slice()}, {}, NOW,
                     heartbeat=60, stale_after=600)
    result = ops.activity(
        changes=[{"event_id": "chg_1", "severity": "WARNING", "verdict": "CRYPTO_CHANGED", "headline": "2 change(s)",
                  "first_detected_at": (NOW - timedelta(hours=2)).isoformat(), "acknowledged": False,
                  "changes": [{"kind": "CRYPTO_ADDED", "subject": "mrdn-swiftgw01 · CBOM · cryptography"}]}],
        patterns=[],
        audit=[{"id": "a1", "action": "control.agent_activated", "target_id": "id-mrdn-swiftgw01",
                "detail": '{"key_id": "ed25519:1", "hostname": "h"}', "outcome": "SUCCESS",
                "created_at": NOW - timedelta(hours=1)},
               {"id": "a2", "action": "auth.login", "created_at": NOW}],
        fleet_view=view, now=NOW)
    kinds = [(e["kind"], e["agents"]) for e in result["events"]]
    assert kinds == [("agent", ["mrdn-swiftgw01"]), ("change", ["mrdn-swiftgw01"])]  # login is not operations
    assert result["events"][0]["detail"] == "hostname h · key id ed25519:1"
    assert result["events"][1]["systems"] == ["SWIFT Gateway"]
    assert result["totals"]["unacknowledged_changes"] == 1 and sum(result["hourly"]["counts"]) == 2


# --------------------------------------------------------------------------- #
# end to end: real agents → the four views
# --------------------------------------------------------------------------- #


def _sample(c, servers):
    from cryptava.performance import Sampler

    for _name, cfg, state in servers:
        base = Path(cfg["proc"]).parent
        cfg["performance_scope"] = "host"
        fakehost.performance_counters(base, 1)
        sampler = Sampler(cfg, cryptava_agent.host_view(cfg), tls_probe=lambda a, p, t: None,
                          hsm_probe=lambda a, p, t: None)
        sampler.sample()
        fakehost.performance_counters(base, 2)
        result = cryptava_agent.send_performance(cfg, state, sampler)
        assert result["delivered"], result.get("error")


def test_the_fleet_and_hosts_answer_from_what_the_agents_sent(bank):
    c, h = bank
    _sample(c, c.bank_servers)
    fleet = c.get("/api/v1/operations/fleet", headers=h)
    assert fleet.status_code == 200, fleet.text
    body = fleet.json()
    agents = {a["name"]: a for a in body["agents"]}
    assert set(agents) == {"mrdn-sbx-dc1-swiftgw01", "mrdn-sbx-dc1-coredb01"}
    swift = agents["mrdn-sbx-dc1-swiftgw01"]
    assert swift["liveness"]["state"] == "LIVE" and swift["registered"] and swift["healthy"]
    assert swift["system"]["name"] == "SWIFT Gateway" and swift["system"]["criticality"] == "tier-0"
    assert swift["host"]["ip_addresses"] == ["10.210.0.4"]
    assert {p["bom"] for p in swift["planes"]} >= {"HBOM", "SBOM", "NBOM", "CBOM", "VBOM"}
    assert swift["source_states"].get("READ", 0) > 0
    assert swift["performance"]["state"] == "SAMPLED" and swift["performance"]["latest"]["cpu_pct"]["value"] == 25.0
    assert body["totals"]["live"] == 2 and body["totals"]["systems"] == ["Core Banking", "SWIFT Gateway"]

    hosts = c.get("/api/v1/operations/hosts", headers=h).json()
    row = next(x for x in hosts["hosts"] if x["agent"] == "mrdn-sbx-dc1-swiftgw01")
    assert {s["name"] for s in row["services"] if s["running"]} >= {"nginx", "sshd"}
    openssl = [lib for lib in row["libraries"] if lib["loaded"]]
    assert openssl and "nginx" in openssl[0]["loaded_by"]
    assert any(a["verdict"] == "SHOR_VULNERABLE" for a in row["algorithms"])
    assert row["performance"]["series"]["cpu_pct"]


def test_monitor_flags_a_silent_tier0_agent(bank):
    c, h = bank
    calm = c.get("/api/v1/operations/monitor", headers=h).json()
    assert not [a for a in calm["alerts"] if a["rule"].startswith("AGENT_")]
    assert calm["fleet"]["totals"]["live"] == 2

    from db.connection.engine import get_engine
    from sqlalchemy import text

    with get_engine().begin() as conn:
        conn.execute(text("UPDATE cp_agents SET last_heartbeat_at = :t WHERE name = 'mrdn-sbx-dc1-swiftgw01'"),
                     {"t": datetime.now(timezone.utc) - timedelta(hours=2)})
    body = c.get("/api/v1/operations/monitor", headers=h).json()
    offline = [a for a in body["alerts"] if a["rule"] == "AGENT_OFFLINE"]
    assert len(offline) == 1 and offline[0]["severity"] == "CRITICAL" and offline[0]["system"] == "SWIFT Gateway"
    assert body["status"]["state"] == "DEGRADED"
    activity = c.get("/api/v1/operations/activity", headers=h).json()
    silent = [e for e in activity["events"] if e["title"] == "Agent went silent"]
    assert [e["agents"] for e in silent] == [["mrdn-sbx-dc1-swiftgw01"]] and silent[0]["severity"] == "HIGH"


def test_activity_lists_enrolment_and_changes(bank):
    c, h = bank
    r = c.get("/api/v1/operations/activity", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    titles = [e["title"] for e in body["events"]]
    assert "Agent enrolled" in titles and "Agent activated" in titles
    changes = [e for e in body["events"] if e["kind"] == "change"]
    assert changes and all(e["at"] for e in body["events"])
    assert [e["at"] for e in body["events"]] == sorted((e["at"] for e in body["events"]), reverse=True)
    enrolled = [e for e in body["events"] if e["title"] == "Agent activated"]
    assert {a for e in enrolled for a in e["agents"]} == {"mrdn-sbx-dc1-swiftgw01", "mrdn-sbx-dc1-coredb01"}
