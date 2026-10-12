"""Threat-intel feed endpoints (deep/30, round 35): list + sync."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/feeds.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("THREAT_INTEL_FEEDS", "")
    monkeypatch.setenv("EGRESS_GUARD", "off")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client


class _Response:
    """Minimal stand-in for the fetch() result sync_feed expects."""

    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_feeds_listing_empty_then_configured(sqlite_app, monkeypatch):
    client = sqlite_app
    # anon first — the TestClient keeps session cookies once logged in
    r = client.get("/api/v1/threat-intel/feeds")
    assert r.status_code == 401  # authenticated surface

    admin = _login(client)
    r = client.get("/api/v1/threat-intel/feeds", headers=admin)
    assert r.status_code == 200
    body = r.json()
    assert body["model"] == "threat-intel-feeds/v1"
    assert body["feeds"] == [] and body["feed_count"] == 0
    assert body["bundle_format"] == "zelnx-threat-intel/v1"

    monkeypatch.setenv("THREAT_INTEL_FEEDS",
                       "nist=https://feeds.example.gov/bundle, cert=https://cert.example.org/bundle")
    get_settings.cache_clear()
    r = client.get("/api/v1/threat-intel/feeds", headers=admin)
    body = r.json()
    assert body["feed_count"] == 2
    assert body["feeds"][0] == {"name": "nist", "url": "https://feeds.example.gov/bundle"}
    # the secret is never part of the listing
    assert "secret" not in str(body).lower()


def test_sync_without_feeds_is_an_explicit_empty_result(sqlite_app):
    client = sqlite_app
    admin = _login(client)
    r = client.post("/api/v1/threat-intel/advisories/sync", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "threat-intel-feeds/sync-v1"
    assert body["feeds_total"] == 0 and body["created"] == 0
    assert "no feeds configured" in body["note"]


def test_sync_requires_admin(sqlite_app):
    r = sqlite_app.post("/api/v1/threat-intel/advisories/sync")
    assert r.status_code == 401


def test_sync_upserts_verified_entries_and_isolates_bad_feeds(
        sqlite_app, monkeypatch):
    client = sqlite_app
    admin = _login(client)
    monkeypatch.setenv("THREAT_INTEL_FEEDS", "good=https://good.example/b, bad=https://bad.example/b")
    monkeypatch.setenv("THREAT_INTEL_FEED_SECRET", "feed-secret-0123456789")
    get_settings.cache_clear()

    # verify_advisory_bundle parses bundle dates back to datetimes;
    # entries reaching _upsert always look like this
    entries = [{
        "advisory_id": "FEED-2026-001", "source": "feed", "advisory_type": "DEPRECATION",
        "algorithm": "SHA-1", "severity": "HIGH",
        "title": "SHA-1 signatures must go",
        "published_at": datetime(2026, 9, 1, tzinfo=timezone.utc),
        "effective_date": None, "summary": None, "url": None, "details": None,
    }]
    captured = {}

    def _fake_sync_feeds(feeds, *, secret, timeout, fetch=None):
        captured["feeds"] = feeds
        captured["secret"] = secret
        return {
            "feeds_total": 2, "feeds_ok": 1,
            "results": [{"feed": "good", "ok": True, "entries": 1},
                        {"feed": "bad", "ok": False, "error": "feed returned 500"}],
            "entries": entries,
        }

    import api.routers.threat_intel as router_mod

    monkeypatch.setattr(router_mod, "sync_feeds", _fake_sync_feeds)
    r = client.post("/api/v1/threat-intel/advisories/sync", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["feeds_ok"] == 1 and body["created"] == 1
    assert body["results"][1]["ok"] is False
    # the endpoint passed exactly the configured feeds + secret through
    assert captured["feeds"][0]["name"] == "good"
    assert captured["secret"] == "feed-secret-0123456789"

    # entries landed in the advisories table — visible via the listing
    r = client.get("/api/v1/threat-intel/advisories", headers=admin,
                   params={"algorithm": "SHA-1"})
    assert r.status_code == 200
    assert any(a["advisory_id"] == "FEED-2026-001" for a in r.json()["advisories"])


def test_sync_bad_feed_only_persists_nothing_from_it(sqlite_app, monkeypatch):
    client = sqlite_app
    admin = _login(client)
    monkeypatch.setenv("THREAT_INTEL_FEEDS", "only=https://only.example/b")
    monkeypatch.setenv("THREAT_INTEL_FEED_SECRET", "feed-secret-0123456789")
    get_settings.cache_clear()

    import api.routers.threat_intel as router_mod

    monkeypatch.setattr(router_mod, "sync_feeds",
                        lambda feeds, **kw: {"feeds_total": 1, "feeds_ok": 0,
                                             "results": [{"feed": "only", "ok": False,
                                                          "error": "bundle rejected: tampered"}],
                                             "entries": []})
    r = client.post("/api/v1/threat-intel/advisories/sync", headers=admin)
    assert r.status_code == 200
    body = r.json()
    assert body["created"] == 0 and body["feeds_ok"] == 0
    r = client.get("/api/v1/threat-intel/advisories", headers=admin)
    assert r.json()["count"] == 0


# ── this deployment AS a feed (round 38) ─────────────────────────────


def _seed_advisories(client):
    """Admin-direct import through the public API surface."""
    admin = _login(client)
    r = client.post("/api/v1/threat-intel/advisories/import", headers=admin,
                    json={"advisories": [{
                        "advisory_id": "SITE-2026-001", "source": "central-site",
                        "advisory_type": "DEPRECATION", "algorithm": "SHA-1",
                        "severity": "HIGH",
                        "title": "SHA-1 signatures rejected from 2027",
                        "published_at": "2026-09-01T00:00:00Z",
                    }]})
    assert r.status_code == 200, r.text


def test_feed_endpoint_serves_a_bundle_sync_feeds_can_consume(sqlite_app, monkeypatch):
    """Round trip: issuing instance -> GET /feed -> consumer's sync_feed."""
    from vendor_intel.threat_intel import sync_feed

    client = sqlite_app
    _seed_advisories(client)

    # no secret configured: the endpoint says so instead of serving unsigned
    r = client.get("/api/v1/threat-intel/feed")
    assert r.status_code == 503
    assert "THREAT_INTEL_FEED_SECRET" in r.json()["detail"]

    monkeypatch.setenv("THREAT_INTEL_FEED_SECRET", "shared-feed-secret-1")
    monkeypatch.setenv("THREAT_INTEL_FEED_TOKEN", "pull-token-1")
    get_settings.cache_clear()
    r = client.get("/api/v1/threat-intel/feed")
    assert r.status_code == 401  # token required now

    r = client.get("/api/v1/threat-intel/feed", params={"token": "pull-token-1"})
    assert r.status_code == 200, r.text
    bundle = r.json()
    assert bundle["package"]["format"] == "zelnx-threat-intel/v1"
    assert len(bundle["package"]["advisories"]) == 1

    # the consumer half of the loop: fetch -> verify -> entries
    result = sync_feed("https://central.example/api/v1/threat-intel/feed",
                       secret="shared-feed-secret-1",
                       fetch=lambda url, timeout: _Response(body=bundle))
    assert result["ok"] is True, result
    assert result["entries"][0]["advisory_id"] == "SITE-2026-001"


def test_feed_endpoint_tamper_evidence_and_empty(sqlite_app, monkeypatch):
    from vendor_intel.threat_intel import sync_feed

    client = sqlite_app
    monkeypatch.setenv("THREAT_INTEL_FEED_SECRET", "shared-feed-secret-1")
    monkeypatch.setenv("THREAT_INTEL_FEED_TOKEN", "")
    get_settings.cache_clear()

    # empty table -> a valid EMPTY bundle, not an error
    r = client.get("/api/v1/threat-intel/feed")
    assert r.status_code == 200
    bundle = r.json()
    assert bundle["package"]["advisories"] == []
    result = sync_feed("https://x", secret="shared-feed-secret-1",
                       fetch=lambda url, timeout: _Response(body=bundle))
    assert result == {"ok": True, "entries": []}

    # a tampered bundle is rejected whole by the consumer
    _seed_advisories(client)
    bundle = client.get("/api/v1/threat-intel/feed").json()
    bundle["package"]["advisories"][0]["severity"] = "CRITICAL"
    result = sync_feed("https://x", secret="shared-feed-secret-1",
                       fetch=lambda url, timeout: _Response(body=bundle))
    assert result["ok"] is False and "rejected" in result["error"]
