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
        # scanner executable -> enable blocked before evaluation reaches ruleset
        r = client.post(f"/api/v1/marketplace/plugins/{up['id']}/evaluate",
                        json={"findings": []})
        assert r.status_code in (409, 422)

    def test_executable_enable_requires_governance_approval(self, client):
        """A trusted signed executable plugin still needs an APPROVED governance
        request (separate approver) before it can be enabled — fail-closed gate."""
        import base64 as _b64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from marketplace.manifest import PluginManifest
        from marketplace.verify import sign_plugin

        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(encoding=Encoding.Raw,
                                             format=PublicFormat.Raw)
        kid = "it-ca"
        assert client.post("/api/v1/marketplace/trusted-keys",
                           json={"key_id": kid,
                                 "public_key_b64": _b64.b64encode(pub).decode()}
                           ).status_code == 201

        content = "def scan(t): return []"
        md = {"plugin_id": "zelnx.gov-gated", "version": "1.0.0",
              "plugin_type": "scanner", "name": "gov gated",
              "content_sha256": _sha(content), "min_platform": "1.0.0"}
        manifest = PluginManifest.from_dict(md)
        sig = sign_plugin(priv, manifest)
        up = client.post("/api/v1/marketplace/plugins", json={
            "manifest": md, "content": content, "signature": sig,
            "signer_key_id": kid, "enable": True,
        }).json()
        # trusted + valid signature, but held at VERIFIED (not auto-enabled)
        assert up["state"] == "VERIFIED"
        assert up["trusted"] is True
        pid = up["id"]

        # enable without approval -> 403
        r = client.post(f"/api/v1/marketplace/plugins/{pid}/enable", json={})
        assert r.status_code == 403, "executable enable must require approval"

        # submit governance request for THIS plugin
        gr = client.post("/api/v1/governance/requests", json={
            "request_type": "plugin_enable_executable",
            "payload": {"plugin_id": "zelnx.gov-gated"},
        }).json()
        gid = gr["id"]
        assert gr["decision"] == "REQUIRES_APPROVAL" and gr["risk_level"] == "HIGH"

        # a PENDING approval still fails the gate
        r = client.post(f"/api/v1/marketplace/plugins/{pid}/enable",
                        json={"approval_id": gid})
        assert r.status_code == 403

        # different approver approves (admin superadmin == requester here, but the
        # test client is the only actor; decision succeeds because in dev the
        # session user is 'admin' for both — SoD is tested separately in
        # governance. We simulate a distinct approver via direct DB update.)
        from db.models.p2 import GovernanceApproval
        from db.connection.session import SessionLocal
        db = SessionLocal()
        row = db.get(GovernanceApproval, gid)
        row.status = "APPROVED"
        row.decision = "APPROVED"
        row.decided_by = "approver-2"
        db.commit()
        db.close()

        r = client.post(f"/api/v1/marketplace/plugins/{pid}/enable",
                        json={"approval_id": gid})
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "ENABLED"

        # approval referencing a DIFFERENT plugin must not enable it
        other = client.post("/api/v1/governance/requests", json={
            "request_type": "plugin_enable_executable",
            "payload": {"plugin_id": "zelnx.some-other"},
        }).json()
        db = SessionLocal()
        row = db.get(GovernanceApproval, other["id"])
        row.status = "APPROVED"
        row.decision = "APPROVED"
        row.decided_by = "approver-2"
        db.commit()
        db.close()
        up2 = client.post("/api/v1/marketplace/plugins", json={
            "manifest": {**md, "plugin_id": "zelnx.gov-gated2",
                         "content_sha256": _sha(content + "v2")},
            "content": content + "v2", "signature": sign_plugin(
                priv, PluginManifest.from_dict({**md, "plugin_id": "zelnx.gov-gated2",
                                                "content_sha256": _sha(content + "v2")})),
            "signer_key_id": kid,
        }).json()
        r = client.post(f"/api/v1/marketplace/plugins/{up2['id']}/enable",
                        json={"approval_id": other["id"]})
        assert r.status_code == 403, "approval must be pinned to the plugin id"


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

    def test_posture_baseline_seal_and_drift(self, client):
        base = client.post("/api/v1/anomaly/baseline", json={
            "findings": [
                {"algorithm": "AES", "key_size": 256, "file_path": "a.java"},
                {"algorithm": "RSA", "key_size": 2048, "file_path": "b.java"},
            ],
        }).json()
        assert base["weak_findings_total"] == 0
        assert len(base["digest"]) == 64

        # identical posture -> no drift
        same = client.post("/api/v1/anomaly/baseline/drift", json={
            "baseline": base,
            "findings": [{"algorithm": "AES", "key_size": 256, "file_path": "c.java"}],
        }).json()
        assert same["drifted"] is False

        # DES appears -> HIGH drift
        drifted = client.post("/api/v1/anomaly/baseline/drift", json={
            "baseline": base,
            "findings": [
                {"algorithm": "AES", "key_size": 256, "file_path": "a.java"},
                {"algorithm": "DES", "key_size": 56, "file_path": "d.java"},
            ],
        }).json()
        assert drifted["drifted"] is True
        assert any(d["kind"] == "new_weak_algorithm" and d["severity"] == "HIGH"
                   for d in drifted["drifts"])

        # tampered baseline rejected
        bad = dict(base)
        bad["weak_findings_total"] = 5
        r = client.post("/api/v1/anomaly/baseline/drift",
                        json={"baseline": bad, "findings": []})
        assert r.status_code == 422


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
