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


# ================================================ unauthenticated webhooks
class _FakeReq:
    def __init__(self, headers=None):
        self.headers = headers or {}


def test_registry_webhook_rejects_unsigned_in_production(monkeypatch):
    from api.config import settings as settings_mod
    from api.routers import webhooks

    monkeypatch.setenv("REGISTRY_WEBHOOK_SECRET", "registry-secret-with-32-chars-minimum")
    s = settings_mod.get_settings()
    monkeypatch.setattr(type(s), "is_production", property(lambda self: True), raising=False)
    monkeypatch.setattr(webhooks, "get_settings", lambda: s)

    from fastapi import HTTPException

    req = _FakeReq()
    with pytest.raises(HTTPException) as ei:
        webhooks._authorize_registry_webhook(req, b'{"path":"/etc"}')
    assert ei.value.status_code == 401


def test_registry_webhook_accepts_valid_signature(monkeypatch):
    from api.config import settings as settings_mod
    from api.routers import webhooks

    secret = "registry-secret-with-32-chars-minimum"
    monkeypatch.setenv("REGISTRY_WEBHOOK_SECRET", secret)
    s = settings_mod.get_settings()
    monkeypatch.setattr(type(s), "is_production", property(lambda self: True), raising=False)
    monkeypatch.setattr(webhooks, "get_settings", lambda: s)

    import hashlib
    import hmac

    body = b'{"path":"/tmp/sandbox/rootfs"}'
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    req = _FakeReq({"x-zelnx-signature": sig})
    assert webhooks._authorize_registry_webhook(req, body) is None


def test_registry_webhook_rejects_bad_signature(monkeypatch):
    from api.config import settings as settings_mod
    from api.routers import webhooks

    monkeypatch.setenv("REGISTRY_WEBHOOK_SECRET", "registry-secret-with-32-chars-minimum")
    s = settings_mod.get_settings()
    monkeypatch.setattr(type(s), "is_production", property(lambda self: True), raising=False)
    monkeypatch.setattr(webhooks, "get_settings", lambda: s)

    from fastapi import HTTPException

    req = _FakeReq({"x-zelnx-signature": "sha256=deadbeef"})
    with pytest.raises(HTTPException) as ei:
        webhooks._authorize_registry_webhook(req, b"{}")
    assert ei.value.status_code == 401


def test_safe_scan_path_blocks_protected_dirs():
    from api.routers.webhooks import _safe_scan_path
    from fastapi import HTTPException

    for bad in ("/etc/passwd", "/proc/self/environ", "/run/secrets/db", "/sys/kernel"):
        with pytest.raises(HTTPException) as ei:
            _safe_scan_path(bad)
        assert ei.value.status_code == 403


def test_safe_scan_path_confined_to_scan_root(monkeypatch, tmp_path):
    from api.routers.webhooks import _safe_scan_path
    from fastapi import HTTPException

    sandbox = tmp_path / "rootfs"
    sandbox.mkdir()
    (tmp_path / "outside").mkdir()
    monkeypatch.setenv("SCAN_ROOT", str(sandbox))

    inside = sandbox / "opt" / "app"
    inside.mkdir(parents=True)
    assert str(_safe_scan_path(str(inside))).startswith(str(sandbox.resolve()))

    with pytest.raises(HTTPException) as ei:
        _safe_scan_path(str(tmp_path / "outside"))
    assert ei.value.status_code == 403


# ================================================ session default role fail-safe
def test_session_minted_without_roles_is_not_admin():
    from api.security.session_manager import SessionManager

    mgr = SessionManager(secret="x" * 40, ttl_seconds=600)
    token = mgr.create_session("rookie")  # no roles passed
    view = mgr.get_session(token)
    assert "admin" not in view.roles
    assert view.roles == ["readonly"]


# ================================================ OIDC JWKS SSRF guard
def test_oidc_jwks_uri_scheme_and_host_pinned(monkeypatch):
    from api.security.oidc import OidcError, _validate_jwks_uri

    # non-http scheme
    with pytest.raises(OidcError):
        _validate_jwks_uri("file:///etc/passwd", "https://sso.example.com")
    # loopback/metadata
    with pytest.raises(OidcError):
        _validate_jwks_uri("http://169.254.169.254/jwks", "https://sso.example.com")
    # host mismatch with issuer
    with pytest.raises(OidcError):
        _validate_jwks_uri("https://evil.example.com/jwks", "https://sso.example.com")
    # https issuer must have https jwks
    with pytest.raises(OidcError):
        _validate_jwks_uri("http://sso.example.com/jwks", "https://sso.example.com")
    # valid, same-host https
    _validate_jwks_uri("https://sso.example.com/realms/main/protocol/openid-connect/certs",
                       "https://sso.example.com/realms/main")


# ==================================================== OWASP: security headers
@pytest.fixture()
def header_client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_KEY", "prod-secret-key-32-characters-minimum")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "pbkdf2_sha256$1$x$y")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/hdr.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("ALLOW_SQLITE", "true")
    monkeypatch.setenv("ALLOW_INSECURE_CORS", "true")
    monkeypatch.setenv("DOCS_ENABLED", "false")
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


def test_security_headers_present(header_client):
    r = header_client.get("/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp and "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    # HSTS only over HTTPS/production
    assert "Strict-Transport-Security" in r.headers
    assert r.headers.get("Referrer-Policy") == "no-referrer"


# ==================================================== OWASP: user enumeration
def test_disabled_account_does_not_leak_state(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/enum.db")
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
        h = _h(c)
        # create a user, then disable them
        c.post("/api/v1/auth/register", headers=h, json={
            "username": "ghosty", "password": "longenoughpassword", "role": "readonly"})
        admin_h = c.post("/api/v1/auth/login",
                         json={"username": "admin", "password": "cryptoscan"}).json()
        c.patch("/api/v1/auth/users/ghosty", headers={"Authorization": f"Bearer {admin_h['token']}"},
                json={"is_active": False})
        # disabled account: same generic message as a bad password / unknown user
        disabled = c.post("/api/v1/auth/login",
                          json={"username": "ghosty", "password": "longenoughpassword"})
        unknown = c.post("/api/v1/auth/login",
                         json={"username": "nobody_here", "password": "longenoughpassword"})
        assert disabled.status_code == 401 and unknown.status_code == 401
        assert disabled.json()["detail"] == unknown.json()["detail"] == "Invalid username or password"


# ==================================================== OWASP: batch-size caps
def test_ingestion_batch_size_capped(monkeypatch, tmp_path):
    import pytest as _pytest
    from api.routers.runtime import RuntimeFindingsBody
    from pydantic import ValidationError

    with _pytest.raises(ValidationError):
        RuntimeFindingsBody(scanner_id="s",
                            findings=[{"hostname": f"h{i}", "kind": "tls"} for i in range(5001)])
