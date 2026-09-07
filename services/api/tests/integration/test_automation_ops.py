"""Integration: cert watch, sector activation, blast radius (no AI/ML)."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"
NOW = datetime(2026, 9, 3, tzinfo=timezone.utc)


def _token():
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=["superadmin"])


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "automation_ops_integration_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {_token()}"
        yield c


class TestSectorActivation:
    def test_list_sectors(self, client):
        r = client.get(f"{API}/automation/sectors")
        assert r.status_code == 200
        ids = {s["sector"] for s in r.json()["sectors"]}
        assert "banking" in ids

    def test_activate_banking_seeds_rules(self, client):
        r = client.post(f"{API}/automation/sectors/banking/activate")
        assert r.status_code == 201, r.text
        body = r.json()
        assert "pci_dss" in body["policy_packs"]
        assert body["seeded_rule_ids"], "banking should seed automation rules"
        # rules now listed by the automation engine
        rules = client.get(f"{API}/automation/rules").json()["rules"]
        rule_ids = {r["rule_id"] for r in rules}
        assert "banking-hsm-change" in rule_ids
        assert "cert-expiry-sector" in rule_ids

    def test_activate_unknown_sector_404(self, client):
        r = client.post(f"{API}/automation/sectors/atlantis/activate")
        assert r.status_code == 404

    def test_seeded_rules_drive_events(self, client):
        # HSM drift in banking should match banking-hsm-change and request approval
        r = client.post(f"{API}/automation/process-event", json={
            "event_kind": "drift_detected",
            "data": {"asset_id": "hsm-9", "asset_class": "payment_hsm", "is_ot": False},
            "asset": {"id": "hsm-9", "asset_kind": "hsm", "has_hsm": True},
        })
        assert r.status_code == 201
        body = r.json()
        matched = {m["rule_id"] for m in body["plan"]["matched_rules"]}
        assert "banking-hsm-change" in matched
        # request_approval is gated
        gated = {a["action"] for a in body["plan"]["requires_approval"]}
        assert "request_approval" in gated


class TestBlastRadius:
    def test_blast_radius_tally(self, client):
        edges = [
            ["hsm-1", "cert-a"], ["hsm-1", "cert-b"],
            ["cert-a", "app-1"], ["app-1", "svc-payments"],
        ]
        nodes = {
            "hsm-1": {"type": "hsm", "criticality": "MISSION_CRITICAL"},
            "cert-a": {"type": "certificate"}, "cert-b": {"type": "certificate"},
            "app-1": {"type": "application"},
            "svc-payments": {"type": "business_service"},
        }
        r = client.post(f"{API}/automation/blast-radius",
                        json={"origin": "hsm-1", "edges": edges, "nodes": nodes})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["impact_layers"]["certificate"] == 2
        assert body["impact_layers"]["business_service"] == 1
        assert "svc-payments" in body["business_services_affected"]

    def test_blast_radius_deterministic(self, client):
        body = {"origin": "a", "edges": [["a", "b"], ["a", "c"]]}
        r1 = client.post(f"{API}/automation/blast-radius", json=body).json()
        r2 = client.post(f"{API}/automation/blast-radius", json=body).json()
        assert r1["affected"] == r2["affected"]


class TestCertWatch:
    def test_cert_watch_empty_store_ok(self, client):
        # no certificates seeded — should still return a well-formed report
        r = client.post(f"{API}/automation/cert-watch")
        assert r.status_code == 200
        body = r.json()
        assert body["source"] == "live_certificates"
        assert isinstance(body["alerts"], list)


class TestCbomVersioning:
    def test_cbom_versioning_and_diff(self, client):
        # Use unique component ids per test run and assert relative version
        # progression (the shared test engine may already hold versions from
        # other modules; the logic under test is the content-addressed diff).
        tag = datetime.now(timezone.utc).strftime("%H%M%S%f")
        a, b, c = f"app-a-{tag}", f"app-b-{tag}", f"app-c-{tag}"
        # v1: two components -> a new version is created (changed)
        r = client.post(f"{API}/automation/cbom/versions", json={"observations": [
            {"component_id": a, "algorithm": "RSA", "key_size": 2048},
            {"component_id": b, "algorithm": "AES", "key_size": 256},
        ]})
        assert r.status_code == 201, r.text
        v1 = r.json()
        assert v1["changed"] is True and v1["version"] >= 1

        # identical (order-independent) -> no new version
        r = client.post(f"{API}/automation/cbom/versions", json={"observations": [
            {"component_id": b, "algorithm": "AES", "key_size": 256},
            {"component_id": a, "algorithm": "RSA", "key_size": 2048},
        ]})
        assert r.json()["changed"] is False

        # add one -> next version with exactly one added component
        r = client.post(f"{API}/automation/cbom/versions", json={"observations": [
            {"component_id": a, "algorithm": "RSA", "key_size": 2048},
            {"component_id": b, "algorithm": "AES", "key_size": 256},
            {"component_id": c, "algorithm": "ECDSA", "key_size": 256},
        ]})
        v2 = r.json()
        assert v2["version"] == v1["version"] + 1 and len(v2["added"]) == 1
        assert v2["added"][0]["id"] == c

        # history reflects the chain
        hist = client.get(f"{API}/automation/cbom/versions").json()
        assert hist["latest_version"] == v2["version"]
        assert hist["versions"][0]["version"] == v2["version"]  # newest first
        # chain link: the newest version's parent is the second-newest version
        assert hist["versions"][0]["parent_fingerprint"] == hist["versions"][1]["fingerprint"]


class TestRiskRecalculation:
    def test_risk_propagates_to_business_service(self, client):
        r = client.post(f"{API}/automation/risk/recalculate", json={
            "assets": {
                "svc": {"type": "business_service", "criticality": "MEDIUM", "name": "Payments"},
                "app": {"type": "application", "criticality": "HIGH"},
                "lib": {"type": "library", "criticality": "LOW",
                        "findings": [{"severity": "CRITICAL"}], "weak_key": True},
            },
            "edges": [["svc", "app"], ["app", "lib"]],
            "changed_assets": ["lib"],
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scores"]["lib"] > 0
        assert body["scores"]["app"] <= body["scores"]["lib"]
        assert "Payments" in body["business_services_affected"]
        assert "lib" in body["recalculated"]

    def test_risk_deterministic(self, client):
        payload = {"assets": {"s": {"type": "business_service", "name": "S"},
                              "l": {"findings": [{"severity": "HIGH"}]}},
                   "edges": [["s", "l"]]}
        a = client.post(f"{API}/automation/risk/recalculate", json=payload).json()
        b = client.post(f"{API}/automation/risk/recalculate", json=payload).json()
        assert a["scores"] == b["scores"]
