"""Field-level audit diffs, remaining surfaces + unified timeline
(advanced/78 P0#1/#4, round 33).

Vendor patch, migration project/task patch, certificate renewal +
ownership, policy override (config-change audit), remediation task
transition — and the merged cross-system timeline over AuditLog +
platform events.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register all tables
from api.config.settings import get_settings


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/auditdiff33.db"
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


def _seed(db_url):
    eng = create_engine(db_url)
    Session = sessionmaker(bind=eng)
    session = Session()
    from db.models.certificate import Certificate
    from db.models.migration_project import MigrationProject, MigrationTask
    from db.models.remediation_task import RemediationTask
    from db.models.vendor import Vendor

    session.add(Vendor(id="vend-1", name="CryptoVendor Inc",
                       criticality="HIGH", security_contact="old@vendor.example"))
    session.add(MigrationProject(id="mig-1", name="PQC migration",
                                 status="PLANNED"))
    session.add(MigrationTask(id="mtask-1", project_id="mig-1",
                              title="Replace 3DES in payments",
                              status="TODO"))
    session.add(Certificate(id="cert-1", fingerprint_sha256="d" * 64,
                            subject="CN=diff-test", renewal_status="NONE"))
    session.add(RemediationTask(id="rtask-1", evidence_id="ev-1", scan_id="scan-1",
                                rule_id="rule.crypto.legacy", status="PROPOSED",
                                original_finding={"algorithm": "3DES"}))
    session.commit()
    session.close()
    eng.dispose()


def _audit_events(client, action):
    r = client.get(f"/api/v1/auth/audit?action={action}", headers=_login(client))
    assert r.status_code == 200, r.text
    return r.json()["events"]


def test_vendor_patch_audits_field_diff(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url)
    admin = _login(client)

    r = client.patch("/api/v1/vendors/vend-1",
                     json={"security_contact": "new@vendor.example",
                           "criticality": "CRITICAL"}, headers=admin)
    assert r.status_code == 200, r.text

    detail = _audit_events(client, "vendor.update")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert changes["security_contact"]["before"] == "old@vendor.example"
    assert changes["security_contact"]["after"] == "new@vendor.example"
    assert changes["criticality"]["before"] == "HIGH"
    assert changes["criticality"]["after"] == "CRITICAL"
    assert detail["summary"] == ["criticality", "security_contact"]


def test_migration_and_task_patch_audit_field_diff(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url)
    admin = _login(client)

    r = client.patch("/api/v1/migrations/mig-1",
                     json={"status": "IN_PROGRESS", "notes": "kickoff done"},
                     headers=admin)
    assert r.status_code == 200, r.text
    detail = _audit_events(client, "migration.update")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert changes["status"]["before"] == "PLANNED"
    assert changes["status"]["after"] == "IN_PROGRESS"
    assert changes["notes"]["after"] == "kickoff done"

    r = client.patch("/api/v1/migrations/tasks/mtask-1",
                     json={"status": "IN_PROGRESS", "owner": "crypto-team"},
                     headers=admin)
    assert r.status_code == 200, r.text
    detail = _audit_events(client, "migration.task_update")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert changes["status"]["before"] == "TODO"
    assert changes["status"]["after"] == "IN_PROGRESS"
    assert changes["owner"]["after"] == "crypto-team"


def test_certificate_renewal_and_ownership_audit_field_diff(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url)
    admin = _login(client)
    fp = "d" * 64

    r = client.patch(f"/api/v1/certificates/{fp}/renewal",
                     json={"status": "PLANNED", "ticket": "OPS-42"},
                     headers=admin)
    assert r.status_code == 200, r.text
    detail = _audit_events(client, "certificate.renewal_update")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert changes["renewal_status"]["before"] == "NONE"
    assert changes["renewal_status"]["after"] == "PLANNED"
    assert changes["renewal_ticket"]["after"] == "OPS-42"

    r = client.post(f"/api/v1/certificates/{fp}/ownership",
                    json={"owner": "platform-team", "reason": "assign owner"},
                    headers=admin)
    assert r.status_code == 200, r.text
    detail = _audit_events(client, "certificate.ownership.assign")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert changes["owner"]["before"] is None
    assert changes["owner"]["after"] == "platform-team"
    assert detail["reason"] == "assign owner"  # context rides alongside the diff


def test_policy_override_audits_config_change(sqlite_app):
    client, _ = sqlite_app
    admin = _login(client)

    # a real rule from the pack
    rules = client.get("/api/v1/policy/rules", headers=admin).json()["rules"]
    assert rules, "policy pack shipped no rules"
    rule_id = rules[0]["rule_id"]

    r = client.put(f"/api/v1/policy/rules/{rule_id}/override",
                   json={"enabled": True, "severity": "LOW",
                         "note": "accepted risk"}, headers=admin)
    assert r.status_code == 200, r.text

    detail = _audit_events(client, "policy.rule_override_set")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    # first-time override: before is absent, after carries the config
    assert changes["severity"]["before"] is None
    assert changes["severity"]["after"] == "LOW"
    assert changes["enabled"]["after"] is True
    assert changes["note"]["after"] == "accepted risk"

    # second write diffs against the stored override, not against nothing
    r = client.put(f"/api/v1/policy/rules/{rule_id}/override",
                   json={"enabled": True, "severity": "MEDIUM",
                         "note": "re-tuned"}, headers=admin)
    assert r.status_code == 200, r.text
    detail = _audit_events(client, "policy.rule_override_set")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert changes["severity"]["before"] == "LOW"
    assert changes["severity"]["after"] == "MEDIUM"


def test_remediation_accept_audits_status_diff(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url)
    admin = _login(client)

    r = client.post("/api/v1/remediation/tasks/rtask-1/accept", headers=admin)
    assert r.status_code == 200, r.text

    detail = _audit_events(client, "remediation.task_accept")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert changes["status"]["before"] == "PROPOSED"
    assert changes["status"]["after"] == "ACCEPTED"


def test_unified_timeline_merges_both_histories(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url)
    admin = _login(client)

    # produce one audit row and one platform event (remediation accept does both)
    r = client.post("/api/v1/remediation/tasks/rtask-1/accept", headers=admin)
    assert r.status_code == 200, r.text

    r = client.get("/api/v1/auth/audit/timeline", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "unified-timeline/v1"
    assert body["sources"]["audit"] >= 1
    assert body["sources"]["platform"] >= 1
    sources = {e["source"] for e in body["entries"]}
    assert sources == {"audit", "platform"}

    # newest-first ordering
    stamps = [e["at"] for e in body["entries"] if e["at"]]
    assert stamps == sorted(stamps, reverse=True)

    # the accept shows up on both sides of the merge
    audit_side = [e for e in body["entries"]
                  if e["source"] == "audit" and e["action"] == "remediation.task_accept"]
    platform_side = [e for e in body["entries"]
                     if e["source"] == "platform" and e["action"] == "remediation.task_accepted"]
    assert audit_side and platform_side
    assert audit_side[0]["detail"]["changes"][0]["field"] == "status"

    # filters: source, actor, action
    r = client.get("/api/v1/auth/audit/timeline",
                   params={"source": "audit", "action": "remediation.task_accept"},
                   headers=admin)
    entries = r.json()["entries"]
    assert entries and all(e["source"] == "audit" for e in entries)
    r = client.get("/api/v1/auth/audit/timeline",
                   params={"source": "audit", "actor": "nobody-here"},
                   headers=admin)
    assert r.json()["entries"] == []
    # platform rows carry actor inside the payload — filterable too
    r = client.get("/api/v1/auth/audit/timeline",
                   params={"source": "platform", "actor": "admin"},
                   headers=admin)
    assert any(e["action"] == "remediation.task_accepted" for e in r.json()["entries"])


def test_timeline_requires_admin(sqlite_app):
    client, _ = sqlite_app
    r = client.get("/api/v1/auth/audit/timeline")
    assert r.status_code == 401
