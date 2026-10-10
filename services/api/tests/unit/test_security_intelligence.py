"""Security-intelligence endpoints: typed contract smoke tests.

These endpoints expose deterministic engines (identity, scan profiles, finding
correlation, verification state, scan triggers). They only depend on the auth
dependency, so a TestClient with a dependency override exercises the real HTTP
contract without a DB or a live scanner.
"""

from __future__ import annotations

import time

import pytest
from fastapi import Request

pytest.importorskip("fastapi")


def _client(monkeypatch):
    from fastapi.testclient import TestClient

    import api.dependencies
    from api.main import create_app

    # The global middleware now validates machine keys before a request reaches
    # dependency overrides. This test keeps its deterministic route contract by
    # providing a verified machine-principal fixture.
    monkeypatch.setattr(api.dependencies, "_resolve_api_key", lambda request: ("apikey:test", ["viewer"], "test-key"))
    app = create_app()
    orig = api.dependencies.get_current_user

    def _override(request: Request) -> str:
        return "test-user"

    app.dependency_overrides[orig] = _override
    return TestClient(app)


def _headers() -> dict[str, str]:
    # The global auth middleware validates this deterministic machine-principal
    # fixture before the route dependency override runs.
    return {"x-api-key": "test"}


def test_profiles_list(monkeypatch):
    c = _client(monkeypatch)
    r = c.get("/api/v1/security/profiles", headers=_headers())
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 7
    ids = {p["id"] for p in body["profiles"]}
    assert {"bank-production", "ot-safe", "pqc-discovery"} <= ids


def test_profile_resolve_never_loosens_sector(monkeypatch):
    c = _client(monkeypatch)
    r = c.post("/api/v1/security/profiles/resolve", headers=_headers(),
               json={"profile": "deep-assessment", "sector": "banking"})
    assert r.status_code == 200
    body = r.json()
    # banking sector clamps the profile back to read-only / low-safe
    assert body["policy"]["scan"]["mode"] == "read-only"
    assert body["profile"]["id"] == "deep-assessment"


def test_profile_resolve_unknown_404(monkeypatch):
    c = _client(monkeypatch)
    r = c.post("/api/v1/security/profiles/resolve", headers=_headers(),
               json={"profile": "nope"})
    assert r.status_code == 404


def test_identity_resolve_merges_cross_scanner(monkeypatch):
    c = _client(monkeypatch)
    r = c.post("/api/v1/security/intelligence/identity/resolve", headers=_headers(),
               json={"observations": [
                   {"source": "network", "ids": {"hostname": "pay01", "ip": "10.10.1.20"}},
                   {"source": "agent", "ids": {"hostname": "pay01", "agent_id": "agent-7"}},
               ]})
    assert r.status_code == 200
    body = r.json()
    assert body["merges"] == 1
    assert len(body["assets"]) == 1
    assert body["assets"][0]["sources"] == ["agent", "network"]


def test_identity_requires_observations(monkeypatch):
    c = _client(monkeypatch)
    r = c.post("/api/v1/security/intelligence/identity/resolve", headers=_headers(), json={})
    assert r.status_code == 422


def test_correlate_deduplicates(monkeypatch):
    c = _client(monkeypatch)
    r = c.post("/api/v1/security/intelligence/correlate", headers=_headers(),
               json={"findings": [
                   {"category": "weak_tls", "asset_id": "a1", "severity": "high", "title": "TLS", "source": "network"},
                   {"category": "weak_tls", "asset_id": "a1", "severity": "high", "title": "TLS", "source": "crypto"},
               ]})
    assert r.status_code == 200
    body = r.json()
    assert body["inputs"] == 2
    assert body["count"] == 1
    assert body["deduped_by"] == 1


def test_risk_chain_compound(monkeypatch):
    c = _client(monkeypatch)
    r = c.post("/api/v1/security/intelligence/chain", headers=_headers(),
               json={"asset_id": "a1",
                     "findings": [
                         {"category": "weak_tls", "severity": "high", "title": "TLS", "source": "network"},
                         {"category": "internet_exposure", "severity": "medium", "title": "Exposed", "source": "cloud"},
                     ],
                     "critical_asset": True, "business_value": "critical"})
    assert r.status_code == 200
    assert r.json()["overall_severity"] == "critical"
    assert r.json()["compound_risk"] is True


def test_asset_state_stale_never_green(monkeypatch):
    c = _client(monkeypatch)
    now = time.time()
    r = c.post("/api/v1/security/intelligence/state", headers=_headers(),
               json={"verification": "VERIFIED", "last_seen_epoch": now - 40 * 86400, "sources": {"crypto": "observed"}})
    assert r.status_code == 200
    body = r.json()
    assert body["health"]["display_status"] in ("stale", "unknown")


def test_schedule_event_mapping(monkeypatch):
    c = _client(monkeypatch)
    r = c.post("/api/v1/security/intelligence/schedule", headers=_headers(),
               json={"cadence": "on_change", "event": "certificate.changed"})
    assert r.status_code == 200
    body = r.json()
    assert body["schedule"]["kind"] == "event"
    assert body["scans_for_event"] == ["crypto", "certificate"]


def test_asset_state_returns_decayed_confidence(monkeypatch):
    """Freshness decay (audit 49 P0#3): the same confidence, priced by age."""
    c = _client(monkeypatch)
    now = time.time()
    base = {"verification": "VERIFIED", "sources": {"crypto": "observed"}}

    # fresh runtime observation: decay is a no-op
    fresh = c.post("/api/v1/security/intelligence/state", headers=_headers(),
                   json={**base, "last_seen_epoch": now, "now": now,
                         "evidence_class": "RUNTIME"})
    assert fresh.status_code == 200
    body = fresh.json()
    assert "decayed_confidence" in body
    assert body["decayed_confidence"]["score"] == pytest.approx(body["confidence"]["score"])

    # 14-day-old runtime observation: two half-lives -> quarter confidence
    old = c.post("/api/v1/security/intelligence/state", headers=_headers(),
                 json={**base, "last_seen_epoch": now - 14 * 86400, "now": now,
                       "evidence_class": "RUNTIME"})
    assert old.status_code == 200
    decayed = old.json()["decayed_confidence"]
    original = old.json()["confidence"]
    assert decayed["score"] == pytest.approx(original["score"] * 0.25, abs=1e-3)
    assert "freshness decay" in decayed["notes"]

    # binary evidence of the same age barely decays
    binary = c.post("/api/v1/security/intelligence/state", headers=_headers(),
                    json={**base, "last_seen_epoch": now - 14 * 86400, "now": now,
                          "evidence_class": "BINARY"})
    assert binary.status_code == 200
    assert binary.json()["decayed_confidence"]["score"] > decayed["score"]

    # never observed: zero freshness, verified floor still holds
    never = c.post("/api/v1/security/intelligence/state", headers=_headers(),
                   json={**base, "verified": True, "now": now})
    assert never.status_code == 200
    assert never.json()["decayed_confidence"]["score"] <= 0.051
