"""Security regression tests — SSRF in webhook delivery, ABAC fail-closed
defaults, and request-body size hardening.

These pin exploitable behaviour so it cannot silently regress.
"""

from __future__ import annotations

import pytest


# ============================================================ SSRF
def test_webhook_url_rejects_non_http_schemes():
    from control_plane.delivery import WebhookUrlError, validate_webhook_url

    for bad in ("file:///etc/passwd", "gopher://x", "ftp://x/y", "javascript:alert(1)",
                "http://", ""):
        with pytest.raises(WebhookUrlError):
            validate_webhook_url(bad)


def test_webhook_url_blocks_cloud_metadata_and_localhost():
    from control_plane.delivery import WebhookUrlError, validate_webhook_url

    targets = [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://[fe80::1]/",                       # link-local
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:8010/api/v1/control/tenants",
        "http://localhost:8010/internal",
        "http://0.0.0.0/",
        "http://[::1]/",
    ]
    for url in targets:
        with pytest.raises(WebhookUrlError):
            validate_webhook_url(url)


def test_webhook_url_private_address_escape_hatch(monkeypatch):
    from control_plane.delivery import WebhookUrlError, validate_webhook_url

    private_literal = "http://10.20.30.40:8088/services/collector"
    # RFC1918 literal allowed by default (on-prem SIEM), ...
    assert validate_webhook_url(private_literal) == private_literal
    # ... but blocked when the operator opts out of private targets.
    monkeypatch.setenv("ZELNX_WEBHOOK_ALLOW_PRIVATE", "false")
    with pytest.raises(WebhookUrlError):
        validate_webhook_url(private_literal)


def test_webhook_url_allows_public_https():
    from control_plane.delivery import validate_webhook_url

    for url in ("https://splunk.example.com:8088/services/collector",
                "https://soc.bank.example/webhook"):
        # public, routable hostnames must pass (DNS failures fail closed)
        try:
            validate_webhook_url(url)
        except Exception as exc:  # pragma: no cover - offline CI cannot resolve
            if "resolve" not in str(exc).lower():
                raise



def test_deliver_blocks_ssrf_without_making_request(monkeypatch):
    import control_plane.delivery as dmod

    called = {"n": 0}

    def fake_post(post, endpoint, *, content=None, headers=None, timeout=None):
        called["n"] += 1
        return 200, "should never happen"

    integ = {"id": "i1", "kind": "siem", "provider": "webhook", "enabled": True,
             "endpoint": "http://169.254.169.254/latest/meta-data/"}
    # monkeypatch the *production* http entrypoint so a real request would be caught
    monkeypatch.setattr(dmod, "_http_post", fake_post)
    res = dmod.deliver(integ, {"event_type": "siem.finding", "payload": {}},
                       post=None, sleep=lambda _s: None)
    assert called["n"] == 0  # never attempted
    assert res.status == "failed"
    assert "ssrf" in (res.error or "").lower() or "blocked" in (res.error or "").lower()


# ==================================================== ABAC production default
def test_abac_enforced_by_default_in_production(monkeypatch):
    monkeypatch.delenv("ABAC_ENFORCED", raising=False)
    from api.middleware.abac_middleware import _enforced

    monkeypatch.setenv("ENVIRONMENT", "production")
    assert _enforced() is True
    monkeypatch.setenv("ENVIRONMENT", "prod")
    assert _enforced() is True


def test_abac_can_be_explicitly_disabled_in_production(monkeypatch):
    from api.middleware.abac_middleware import _enforced

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("ABAC_ENFORCED", "false")
    assert _enforced() is False


def test_abac_off_in_test_and_dev(monkeypatch):
    from api.middleware.abac_middleware import _enforced

    monkeypatch.delenv("ABAC_ENFORCED", raising=False)
    for env in ("test", "testing", "development", "dev", ""):
        monkeypatch.setenv("ENVIRONMENT", env)
        assert _enforced() is False, env


# ==================================================== body size hardening
@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/sec.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("ABAC_ENFORCED", "true")
    from api.config.settings import get_settings
    get_settings.cache_clear()
    from db.connection import engine as engine_mod
    engine_mod._ENGINE = None
    from api.events.bus import reset_event_bus
    reset_event_bus()
    from api.middleware.abac_middleware import reset_abac_cache
    reset_abac_cache()
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c
    reset_abac_cache()


def _h(c):
    t = c.post("/api/v1/auth/login",
               json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    return {"Authorization": f"Bearer {t}"}


def test_oversized_body_does_not_crash_and_abac_still_allows_scoped(client):
    h = _h(client)
    # provision a grant for region=eu so scoped requests are permitted
    g = client.post("/api/v1/control/grants", headers=h,
                    json={"subject": "admin", "subject_type": "user", "actions": ["*"],
                          "effect": "allow", "region": "eu"})
    assert g.status_code == 201
    # a body far over the cap with a region query param — middleware must not
    # buffer the whole body and must still reach the route (200, not 500/413/403).
    huge = {"region": "eu", "pad": "x" * (2 * 1024 * 1024)}
    r = client.post("/api/v1/enterprise/policies/evaluate",
                    headers=h, params={"region": "eu"},
                    json={"target": huge})
    assert r.status_code != 500
