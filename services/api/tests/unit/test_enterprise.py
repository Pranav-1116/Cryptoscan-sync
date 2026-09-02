"""P1 enterprise API tests: policy-as-code, compliance, ITSM, CMDB/SIEM,
regions/DR, crypto KB, air-gapped signed transfer."""

from __future__ import annotations

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/ent.db")
    monkeypatch.setenv("NEO4J_URI", "")
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


def _h(c):
    t = c.post("/api/v1/auth/login",
               json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    return {"Authorization": f"Bearer {t}"}


# ---------------------------------------------------------- policy as code
def test_policy_as_code_versioned_and_evaluated(client):
    h = _h(client)
    p = client.put("/api/v1/enterprise/policies", headers=h, json={
        "name": "banking-tls", "layer": "sector", "sector": "banking",
        "rules": [{"id": "tls-min", "path": "tls.version", "op": "gte", "value": 1.2}]})
    assert p.status_code in (200, 201)
    version = p.json()["version"]
    assert len(version) == 16

    # weak TLS fails
    fail = client.post("/api/v1/enterprise/policies/evaluate", headers=h, json={
        "sector": "banking", "target": {"tls": {"version": 1.0}}})
    assert fail.json()["verdict"] == "FAIL"
    ok = client.post("/api/v1/enterprise/policies/evaluate", headers=h, json={
        "sector": "banking", "target": {"tls": {"version": 1.3}}})
    assert ok.json()["verdict"] == "PASS"


def test_policy_layers_merge(client):
    h = _h(client)
    client.put("/api/v1/enterprise/policies", headers=h, json={
        "name": "base", "layer": "organization",
        "rules": [{"id": "no-rc4", "path": "cipher", "op": "ne", "value": "rc4"}]})
    client.put("/api/v1/enterprise/policies", headers=h, json={
        "name": "risk-warn", "layer": "risk",
        "rules": [{"id": "key-size", "path": "key_bits", "op": "gte", "value": 2048, "effect": "warn"}]})
    # rc4 present -> FAIL; key small -> WARN. FAIL wins.
    res = client.post("/api/v1/enterprise/policies/evaluate", headers=h, json={
        "target": {"cipher": "rc4", "key_bits": 1024}})
    assert res.json()["verdict"] == "FAIL"
    # clean cipher, small key -> WARN
    res2 = client.post("/api/v1/enterprise/policies/evaluate", headers=h, json={
        "target": {"cipher": "aes-gcm", "key_bits": 1024}})
    assert res2.json()["verdict"] == "WARN"


# ------------------------------------------------------------- compliance
def test_compliance_traceable_status(client):
    h = _h(client)
    client.post("/api/v1/enterprise/compliance/controls", headers=h, json={
        "framework": "NIST", "control_id": "SC-8", "assets": ["a1", "a2"]})
    client.post("/api/v1/enterprise/compliance/controls", headers=h, json={
        "framework": "NIST", "control_id": "SC-12", "assets": ["a1"]})
    posture = client.post("/api/v1/enterprise/compliance/evaluate", headers=h, json={
        "findings": [{"control_id": "SC-12", "asset_id": "a1", "status": "open"}],
        "evidence": [{"control_id": "SC-8", "asset_id": "a1", "current": True},
                     {"control_id": "SC-8", "asset_id": "a2", "current": True}]}).json()
    assert posture["gaps"] == 1
    assert posture["not_evidenced"] == 0
    assert posture["compliant"] == 1


# ------------------------------------------------------------------ ITSM
def test_itsm_ticket_lifecycle(client):
    h = _h(client)
    t = client.post("/api/v1/enterprise/itsm/tickets", headers=h, json={
        "title": "RSA-1024 on hsm-1", "finding_id": "f-9", "severity": "high"}).json()
    tid = t["ticket_id"]
    assert t["state"] == "open"
    for action, expect in [("triage", "triaged"), ("assign", "assigned"),
                           ("start", "in_progress"), ("migrate", "in_migration"),
                           ("validate", "validation"), ("pass", "resolved"),
                           ("close", "closed")]:
        r = client.post(f"/api/v1/enterprise/itsm/tickets/{tid}/transition", headers=h,
                        json={"action": action})
        assert r.json()["state"] == expect
    # invalid transition rejected
    bad = client.post(f"/api/v1/enterprise/itsm/tickets/{tid}/transition", headers=h,
                      json={"action": "start"})
    assert bad.status_code == 409


# ----------------------------------------------------------------- CMDB
def test_cmdb_import_resolution(client):
    h = _h(client)
    r = client.post("/api/v1/enterprise/integrations", headers=h, json={
        "kind": "cmdb", "provider": "servicenow", "name": "corp-cmdb"})
    assert r.status_code == 201
    res = client.post("/api/v1/enterprise/integrations/cmdb/resolve", headers=h, json={
        "records": [{"serial": "S1", "owner": "secops", "business_unit": "payments",
                      "criticality": "tier1", "ci_id": "CI-1"}],
        "discovered": [{"serial": "S1", "asset_type": "hsm"},
                        {"fqdn": "new-1.local", "asset_type": "server"}]}).json()
    assert res["matched"] == 1 and res["new_unmatched"] == 1
    assert res["enriched"][0]["business_unit"] == "payments"


# ------------------------------------------------------------------ SIEM
def test_siem_export_to_queue(client):
    h = _h(client)
    r = client.post("/api/v1/enterprise/integrations/siem/export", headers=h, json={
        "provider": "splunk",
        "events": [{"category": "alert", "severity": "critical", "name": "weak-tls", "asset": "a1"},
                   {"category": "unknown"}]})
    assert r.json()["exported"] == 1
    assert r.json()["cef"][0].startswith("CEF:0")


# ------------------------------------------------------------- regions/DR
def test_regions_and_dr(client):
    h = _h(client)
    client.put("/api/v1/enterprise/regions", headers=h, json={
        "code": "uae-primary", "name": "UAE Primary", "is_primary": True,
        "healthy": True, "rpo_minutes": 60,
        "last_backup_at": "2026-09-06T11:50:00+00:00"})
    client.put("/api/v1/enterprise/regions", headers=h, json={
        "code": "uae-dr", "name": "UAE DR", "is_primary": False, "healthy": True})
    health = client.get("/api/v1/enterprise/regions/health", headers=h).json()
    primary = next(r for r in health["regions"] if r["is_primary"])
    assert primary["rpo_within_target"] is True
    assert any(r["failover_ready"] for r in health["regions"])


# ------------------------------------------------------------- crypto KB
def test_crypto_kb_lookup_and_override(client):
    h = _h(client)
    r = client.get("/api/v1/enterprise/crypto-kb?algorithm=rsa-2048", headers=h).json()
    assert r["builtin"] is not None and r["builtin"]["status"] == "acceptable"
    # add an org override
    client.put("/api/v1/enterprise/crypto-kb", headers=h, json={
        "algorithm": "custom-cipher-x", "status": "weak", "category": "symmetric"})
    listed = client.get("/api/v1/enterprise/crypto-kb", headers=h).json()
    assert any(e["algorithm"] == "custom-cipher-x" for e in listed["entries"])


# ------------------------------------------------- wired findings pipeline
def test_pipeline_evaluates_supplied_findings(client):
    h = _h(client)
    # policy that rejects DISALLOWED status algorithms
    client.put("/api/v1/enterprise/policies", headers=h, json={
        "name": "no-disallowed", "layer": "organization",
        "rules": [{"id": "r1", "path": "status", "op": "ne", "value": "DISALLOWED"}]})
    client.post("/api/v1/enterprise/compliance/controls", headers=h, json={
        "framework": "NIST-CSF", "control_id": "SC-12", "assets": ["a1"]})
    out = client.post("/api/v1/enterprise/pipeline/evaluate", headers=h, json={
        "findings": [
            {"algorithm": "RSA", "key_size": 1024, "asset_id": "a1", "status": "DISALLOWED"},
            {"algorithm": "ECDSA", "key_size": 256, "asset_id": "a2", "status": "ALLOWED",
             "tls_version": "TLSv1.3"}]})
    body = out.json()
    assert body["total_findings"] == 2 and body["risks"] >= 1
    assert body["posture"] is not None
    assert any(v["is_risk"] for v in body["verdicts"])


def test_cmdb_resolve_persists_identities(client):
    h = _h(client)
    client.post("/api/v1/enterprise/integrations", headers=h, json={
        "kind": "cmdb", "provider": "servicenow", "name": "cmdb"})
    res = client.post("/api/v1/enterprise/integrations/cmdb/resolve", headers=h, json={
        "records": [{"serial": "S-9", "owner": "secops", "business_unit": "payments",
                      "criticality": "tier1", "ci_id": "CI-9"}],
        "discovered": [{"serial": "S-9", "asset_type": "hsm"}]}).json()
    assert res["identities_persisted"] == 1
    assets = client.get("/api/v1/control/assets", headers=h).json()["assets"]
    persisted = [a for a in assets if "secops" == a.get("owner")]
    assert persisted and persisted[0]["business_unit"] == "payments"


def test_worker_tick_processes_queued_events(client):
    h = _h(client)
    client.post("/api/v1/control/events/enqueue", headers=h,
                json={"event_type": "siem.test", "priority": "normal", "payload": {"x": 1}})
    client.post("/api/v1/control/events/enqueue", headers=h,
                json={"event_type": "scan.start", "priority": "high",
                      "payload": {"domain": "cloud"}})
    tick = client.post("/api/v1/control/orchestrator/tick", headers=h,
                       json={"worker_id": "w1", "batch": 5}).json()
    assert tick["processed"] == 2 and tick["failed"] == []
    # queue drains
    remaining = client.get("/api/v1/control/events/queue?status_filter=queued", headers=h).json()["events"]
    assert remaining == []


def test_worker_tick_emergency_stop_blocks(client):
    h = _h(client)
    client.post("/api/v1/control/events/enqueue", headers=h,
                json={"event_type": "scan.start", "priority": "high", "payload": {"domain": "network"}})
    client.post("/api/v1/control/safe-scan/emergency-stop", headers=h, json={"engaged": True})
    tick = client.post("/api/v1/control/orchestrator/tick", headers=h, json={"batch": 5}).json()
    assert tick["processed"] == 0 and tick["blocked"]
    client.post("/api/v1/control/safe-scan/emergency-stop", headers=h, json={"engaged": False})


def test_airgap_bundle_carries_findings(client):
    h = _h(client)
    bundle = client.post("/api/v1/enterprise/airgap/bundle", headers=h, json={
        "secret": "airgap-bundle-secret", "include_findings": True}).json()
    assert bundle["package"]["content_hash"]
    assert "findings" in bundle["document_keys"]


def test_control_health_includes_components(client):
    h = _h(client)
    r = client.get("/api/v1/control/health", headers=h).json()
    assert "components" in r and "database" in r["components"]
    assert r["status"] in {"ok", "degraded", "critical"}


# ------------------------------------------------------- air-gapped transfer
def test_signed_export_import_roundtrip_and_tamper(client):
    h = _h(client)
    doc = {"findings": [{"id": "f1", "severity": "high"}], "evidence": ["ev1"]}
    exp = client.post("/api/v1/enterprise/airgap/export", headers=h,
                      json={"document": doc, "secret": "airgapped-shared-secret"})
    pkg = exp.json()["package"]
    assert pkg["content_hash"]
    imp = client.post("/api/v1/enterprise/airgap/import", headers=h,
                      json={"package": pkg, "secret": "airgapped-shared-secret"})
    assert imp.json()["accepted"] is True
    # tampered package rejected
    bad = client.post("/api/v1/enterprise/airgap/import", headers=h,
                      json={"package": {**pkg, "document": {"findings": []}},
                            "secret": "airgapped-shared-secret"})
    assert bad.status_code == 422
    # wrong secret rejected
    bad2 = client.post("/api/v1/enterprise/airgap/import", headers=h,
                       json={"package": pkg, "secret": "wrong-secret-xx"})
    assert bad2.status_code == 422
