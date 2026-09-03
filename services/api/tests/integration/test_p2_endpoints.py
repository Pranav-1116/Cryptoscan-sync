"""Integration tests for the P2 deterministic enterprise features.

Covers the four new routers end-to-end against a real SQLite DB with a real
admin session: marketplace (hash-pin / signature quarantine), data lake
(chained, tamper-evident exports), anomaly detection (statistical, no ML), and
governance (rule-based approvals + migration validation). No AI/ML.

The shared api/tests/conftest autouse fixture flips SECRET_KEY / DATABASE_URL,
so this module pins both before building the app and lets the app lifespan
create the schema and bootstrap the admin account.
"""

from __future__ import annotations

import hashlib
import os
import tempfile

import pytest
from fastapi.testclient import TestClient


def _p2_token() -> str:
    from api.security.session_manager import SessionManager

    return SessionManager(
        secret="test-secret-key-for-sessions-min-32-chars"
    ).create_session("admin", roles=["superadmin"])


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"

    db_file = os.path.join(tempfile.gettempdir(), "p2_integration_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {_p2_token()}"
        yield c


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ================================================================ marketplace
class TestMarketplace:
    def test_unsigned_executable_plugin_quarantined(self, client):
        content = "def scan(): return []"
        r = client.post("/api/v1/marketplace/plugins", json={
            "manifest": {"plugin_id": "zelnx.x", "version": "1.0.0",
                         "plugin_type": "scanner", "name": "X",
                         "content_sha256": _sha(content)},
            "content": content, "enable": True,
        })
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["state"] == "QUARANTINED"
        assert any("not signed" in e for e in body["verify_errors"])

    def test_tampered_content_quarantined(self, client):
        r = client.post("/api/v1/marketplace/plugins", json={
            "manifest": {"plugin_id": "zelnx.bad", "version": "1.0.0",
                         "plugin_type": "ruleset", "name": "bad",
                         "content_sha256": _sha("original")},
            "content": "tampered payload",
        })
        assert r.json()["state"] == "QUARANTINED"

    def test_data_ruleset_verified_and_enabled(self, client):
        content = "rules: [DES->AES-GCM]"
        r = client.post("/api/v1/marketplace/plugins", json={
            "manifest": {"plugin_id": "zelnx.pqc", "version": "1.0.0",
                         "plugin_type": "ruleset", "name": "PQC",
                         "content_sha256": _sha(content)},
            "content": content, "enable": True,
        })
        body = r.json()
        assert body["state"] == "ENABLED"

    def test_quarantined_plugin_cannot_be_enabled(self, client):
        content = "code"
        up = client.post("/api/v1/marketplace/plugins", json={
            "manifest": {"plugin_id": "zelnx.q", "version": "1.0.0",
                         "plugin_type": "scanner", "name": "q",
                         "content_sha256": _sha(content)},
            "content": content,
        }).json()
        r = client.post(f"/api/v1/marketplace/plugins/{up['id']}/enable")
        assert r.status_code == 409

    def test_unauthenticated_rejected(self):
        from api.main import create_app

        app = create_app()
        with TestClient(app) as c:
            assert c.get("/api/v1/marketplace/plugins").status_code == 401

    def test_ruleset_evaluate_deterministic_gate(self, client):
        import json as _json

        ruleset = {"name": "baseline", "version": "1.0.0",
                   "rules": [{"id": "DES-FAIL", "algorithm": "DES",
                              "decision": "FAIL", "message": "DES is broken"}]}
        content = _json.dumps(ruleset)
        up = client.post("/api/v1/marketplace/plugins", json={
            "manifest": {"plugin_id": "zelnx.rs-gate", "version": "1.0.0",
                         "plugin_type": "ruleset", "name": "gate",
                         "content_sha256": _sha(content)},
            "content": content, "enable": True,
        }).json()
        assert up["state"] == "ENABLED"
        r = client.post(f"/api/v1/marketplace/plugins/{up['id']}/evaluate",
                        json={"findings": [
                            {"algorithm": "DES", "file_path": "a.java"},
                            {"algorithm": "AES", "file_path": "b.java"},
                        ]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["gate"] == "FAIL" and body["fail_count"] == 1
        assert body["results"][0]["gated"] is True
        assert body["results"][1]["gated"] is False

    def test_ruleset_evaluate_rejects_non_ruleset(self, client):
        content = "def scan(): return []"
        up = client.post("/api/v1/marketplace/plugins", json={
            "manifest": {"plugin_id": "zelnx.scanner-x", "version": "1.0.0",
                         "plugin_type": "scanner", "name": "sx",
                         "content_sha256": _sha(content)},
            "content": content,
        }).json()
        # quarantine to bypass executable gating for the 422 check path:
        r = client.post(f"/api/v1/marketplace/plugins/{up['id']}/evaluate",
                        json={"findings": []})
        assert r.status_code in (409, 422)


# ================================================================ data lake
class TestDataLake:
    def test_batches_chain_and_verify(self, client):
        b1 = client.post("/api/v1/datalake/export",
                         json={"lake_id": "it-lake", "records": [{"id": "a"}, {"id": "b"}]}).json()
        b2 = client.post("/api/v1/datalake/export",
                         json={"lake_id": "it-lake", "records": [{"id": "c"}]}).json()
        assert b1["batch_id"] == 1 and b2["batch_id"] == 2
        assert b2["previous_digest"] == b1["chain_digest"]

        v = client.post(f"/api/v1/datalake/verify/{b2['id']}").json()
        assert v["verified"] is True
        assert v["chain_errors"] == [] and v["batch_errors"] == []

    def test_lake_listing_shows_head(self, client):
        r = client.get("/api/v1/datalake/batches", params={"lake_id": "it-lake"})
        body = r.json()
        assert body["head"]
        assert len(body["batches"]) == 2


# ================================================================ anomaly
class TestAnomaly:
    def test_spike_detected_and_persisted(self, client):
        r = client.post("/api/v1/anomaly/analyze", json={
            "metric": "findings", "values": [10, 11, 9, 10, 12, 10, 11, 9, 10, 500],
            "persist": True,
        })
        body = r.json()
        assert body["anomaly_count"] >= 1
        rules = {a["rule"] for a in body["anomalies"]}
        assert "zscore" in rules or "rate_of_change" in rules

    def test_stable_series_no_false_positive(self, client):
        r = client.post("/api/v1/anomaly/analyze", json={
            "metric": "findings", "values": [10, 10, 11, 9, 10, 10, 11, 10],
        })
        assert r.json()["anomaly_count"] == 0

    def test_flags_listed(self, client):
        r = client.get("/api/v1/anomaly/flags", params={"status": "OPEN"})
        assert r.status_code == 200
        assert isinstance(r.json()["flags"], list)


# ================================================================ governance
class TestGovernance:
    def test_low_risk_auto_approved(self, client):
        r = client.post("/api/v1/governance/requests",
                        json={"request_type": "report_export"})
        assert r.status_code == 201, r.text
        assert r.json()["decision"] == "AUTO_APPROVED"

    def test_high_risk_requires_approval(self, client):
        r = client.post("/api/v1/governance/requests",
                        json={"request_type": "plugin_enable_executable"})
        body = r.json()
        assert body["decision"] == "REQUIRES_APPROVAL"
        assert body["status"] == "PENDING"

    def test_secret_material_denied(self, client):
        r = client.post("/api/v1/governance/requests",
                        json={"request_type": "config_change",
                              "payload": {"api_secret": "AKIAXXXX"}})
        assert r.json()["decision"] == "DENIED"

    def test_migration_validation_pass_and_fail(self, client):
        fail = client.post("/api/v1/governance/migration/validate", json={
            "system_id": "mv1",
            "pre_findings": [{"algorithm": "DES", "file_path": "a.java", "line_number": 1, "system_id": "mv1"}],
            "post_findings": [{"algorithm": "DES", "file_path": "a.java", "line_number": 1, "system_id": "mv1"}],
            "pre_covered_assets": ["mv1"], "post_covered_assets": ["mv1"],
        }).json()
        assert fail["status"] == "FAIL"

        ok = client.post("/api/v1/governance/migration/validate", json={
            "system_id": "mv2",
            "pre_findings": [{"algorithm": "DES", "file_path": "b.java", "line_number": 2, "system_id": "mv2"}],
            "post_findings": [{"algorithm": "AES-GCM", "file_path": "b.java", "line_number": 2, "system_id": "mv2"}],
            "pre_covered_assets": ["mv2"], "post_covered_assets": ["mv2"],
        }).json()
        assert ok["status"] == "PASS"
