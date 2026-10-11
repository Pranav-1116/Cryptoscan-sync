"""Site security surfaces (round 31): offline license, external secrets, zero-trust PDP.

advanced/73 P0#1, advanced/75 P0#1, advanced/82.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

# ── offline license ──────────────────────────────────────────────────

from api.security.license import (
    LicenseError,
    issue_license,
    license_status,
    verify_license,
)

KEY = "license-signing-key-0123456789"


def _license(expires_in_days=30, **over):
    return issue_license(
        licensee="Bank of Coimbatore", plan="AIRGAP",
        features=["scanning", "cbom", "airgap"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=expires_in_days),
        site_id="site-001", issuer="zelinx-sales", signing_key=KEY, **over)


def test_license_issue_and_verify_round_trip():
    package = _license()
    result = verify_license(package, signing_key=KEY, site_id="site-001")
    assert result["valid"] is True
    assert result["plan"] == "AIRGAP"
    assert set(result["features"]) == {"scanning", "cbom", "airgap"}
    assert 29 <= result["days_remaining"] <= 30


def test_license_tamper_rejected():
    package = _license()
    package["license"]["plan"] = "ENTERPRISE"  # forged after signing
    with pytest.raises(LicenseError) as exc:
        verify_license(package, signing_key=KEY)
    assert exc.value.code == "TAMPERED"


def test_license_wrong_key_rejected():
    package = _license()
    with pytest.raises(LicenseError) as exc:
        verify_license(package, signing_key="another-key-entirely-1234")
    assert exc.value.code == "TAMPERED"


def test_license_expiry_and_future():
    expired = issue_license(
        licensee="x", plan="PROFESSIONAL", features=["scanning"],
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        site_id="s", issuer="i", signing_key=KEY,
        issued_at=datetime.now(timezone.utc) - timedelta(days=60))
    with pytest.raises(LicenseError) as exc:
        verify_license(expired, signing_key=KEY)
    assert exc.value.code == "EXPIRED"

    future = issue_license(
        licensee="x", plan="PROFESSIONAL", features=["scanning"],
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        site_id="s", issuer="i", signing_key=KEY,
        issued_at=datetime.now(timezone.utc) + timedelta(days=5))
    with pytest.raises(LicenseError) as exc:
        verify_license(future, signing_key=KEY)
    assert exc.value.code == "NOT_YET_VALID"


def test_license_site_binding_and_known_features():
    package = _license()
    with pytest.raises(LicenseError) as exc:
        verify_license(package, signing_key=KEY, site_id="site-999")
    assert exc.value.code == "SITE_MISMATCH"
    with pytest.raises(LicenseError):
        issue_license(licensee="x", plan="PROFESSIONAL",
                      features=["not-a-feature"],
                      expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                      site_id="s", issuer="i", signing_key=KEY)
    with pytest.raises(LicenseError):
        issue_license(licensee="x", plan="MADE_UP",
                      features=["scanning"],
                      expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                      site_id="s", issuer="i", signing_key=KEY)


def test_license_status_never_raises(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    status = license_status(signing_key=KEY, raw_license=json.dumps(_license()),
                            site_id="site-001")
    assert status["valid"] is True
    bad = license_status(signing_key=KEY, raw_license="not-json", site_id="site-001")
    assert bad["valid"] is False and bad["code"] == "MALFORMED"
    nok = license_status(signing_key="", raw_license="{}")
    assert nok["valid"] is False and nok["code"] in {"MALFORMED", "MISSING_KEY"}


# ── external secrets / vault ─────────────────────────────────────────

from api.security.vault import (  # noqa: E402
    SecretResolutionError,
    VaultKVProvider,
    is_reference,
    resolve_secret,
    resolve_settings_secrets,
    secret_status,
)


def test_env_and_file_providers(tmp_path):
    import os

    os.environ["TEST_SCAN_TOKEN"] = "tok-123"
    assert resolve_secret("env:TEST_SCAN_TOKEN") == "tok-123"
    secret_file = tmp_path / "db-password"
    secret_file.write_text("  hunter2-\n")
    assert resolve_secret(f"file:{secret_file}") == "hunter2-"
    assert resolve_secret("plain-value-untouched") == "plain-value-untouched"
    with pytest.raises(SecretResolutionError):
        resolve_secret("env:TEST_SCAN_TOKEN_MISSING")
    with pytest.raises(SecretResolutionError):
        resolve_secret(f"file:{tmp_path / 'nope'}")


def test_vault_provider_kv2_read(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.internal:8200")
    monkeypatch.setenv("VAULT_TOKEN", "hvs.test-token")
    from api.config.settings import get_settings

    get_settings.cache_clear()

    calls = {}

    def stub_fetch(method, url, headers, body, timeout):
        calls["url"] = url
        calls["token"] = headers.get("X-Vault-Token")
        assert method == "GET"
        return 200, json.dumps({"data": {"data": {"password": "vault-secret-9"}}})

    provider = VaultKVProvider(fetch=stub_fetch)
    value = provider.resolve("vault://secret/scandb/admin/password")
    assert value == "vault-secret-9"
    assert calls["url"] == "https://vault.internal:8200/v1/secret/data/scandb/admin"
    assert calls["token"] == "hvs.test-token"


def test_vault_provider_fails_loud(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.internal:8200")
    monkeypatch.setenv("VAULT_TOKEN", "hvs.test-token")
    from api.config.settings import get_settings

    get_settings.cache_clear()

    def stub_404(method, url, headers, body, timeout):
        return 404, "not found"

    with pytest.raises(SecretResolutionError):
        VaultKVProvider(fetch=stub_404).resolve("vault://secret/x/y")

    def stub_missing_key(method, url, headers, body, timeout):
        return 200, json.dumps({"data": {"data": {"other": "value"}}})

    with pytest.raises(SecretResolutionError):
        VaultKVProvider(fetch=stub_missing_key).resolve("vault://secret/x/y")


def test_startup_resolution_replaces_reference_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("METRICS_TOKEN", "env:TEST_METRICS_TOKEN")
    monkeypatch.setenv("TEST_METRICS_TOKEN", "resolved-metrics-token")
    secret_file = tmp_path / "smtp"
    secret_file.write_text("smtp-password-resolved\n")
    monkeypatch.setenv("SMTP_PASSWORD", f"file:{secret_file}")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    settings = get_settings()
    assert is_reference(settings.METRICS_TOKEN)
    report = resolve_settings_secrets(strict=True)
    assert settings.METRICS_TOKEN == "resolved-metrics-token"
    assert settings.SMTP_PASSWORD == "smtp-password-resolved"
    assert report["resolved"] >= 2
    assert "METRICS_TOKEN" in report["resolved_fields"]
    # status surface after resolution: no references remain (they were
    # replaced in place) and no resolved value ever leaks
    status = secret_status()
    assert status["references"] == []
    assert "resolved-metrics-token" not in json.dumps(status)
    assert "smtp-password-resolved" not in json.dumps(status)


def test_startup_resolution_fails_loud(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("METRICS_TOKEN", "env:TEST_MISSING_VARIABLE_XYZ")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    with pytest.raises(SecretResolutionError):
        resolve_settings_secrets(strict=True)


# ── zero-trust PDP ───────────────────────────────────────────────────

from api.security.pdp import (  # noqa: E402
    PolicyError,
    evaluate_embedded,
    evaluate_opa,
    load_policies,
    validate_policy_document,
    zero_trust_decision,
)

POLICY = {
    "format": "zelnx-zero-trust/v1",
    "rules": [
        {"id": "no-mutations-for-viewers",
         "effect": "deny", "roles": ["viewer", "readonly"],
         "methods": ["POST", "PUT", "PATCH", "DELETE"],
         "paths": ["/api/v1/*"]},
        {"id": "legacy-service-blocked",
         "effect": "deny", "principals": ["svc-legacy"],
         "paths": ["/api/v1/crypto/*"]},
        {"id": "auditors-may-read-crypto",
         "effect": "allow", "roles": ["auditor"],
         "methods": ["GET"], "paths": ["/api/v1/crypto/*"]},
    ],
}


def test_rule_matching_and_deny_wins():
    doc = validate_policy_document(POLICY)
    # viewer POST → deny
    d = evaluate_embedded(doc, principal="ana", roles=["viewer"],
                          method="POST", path="/api/v1/systems/sys-1")
    assert d["decision"] == "DENY" and d["matched_rules"] == ["no-mutations-for-viewers"]
    # auditor GET → allow (but never a bypass)
    d = evaluate_embedded(doc, principal="bob", roles=["auditor"],
                          method="GET", path="/api/v1/crypto/live/state")
    assert d["decision"] == "ALLOW"
    # unlisted shape → NOT_APPLICABLE
    d = evaluate_embedded(doc, principal="bob", roles=["auditor"],
                          method="GET", path="/api/v1/systems")
    assert d["decision"] == "NOT_APPLICABLE"
    # deny beats allow when both match
    both = {"format": "zelnx-zero-trust/v1", "rules": [
        {"id": "a", "effect": "allow", "roles": ["auditor"]},
        {"id": "b", "effect": "deny", "roles": ["auditor"],
         "methods": ["GET"]},
    ]}
    d = evaluate_embedded(validate_policy_document(both),
                          principal="b", roles=["auditor"], method="GET", path="/x")
    assert d["decision"] == "DENY"


def test_policy_document_validation():
    with pytest.raises(PolicyError):
        validate_policy_document({"rules": "nope"})
    with pytest.raises(PolicyError):
        validate_policy_document({"rules": [{"id": "x", "effect": "maybe"}]})
    with pytest.raises(PolicyError):
        validate_policy_document({"rules": [{"id": "x", "effect": "deny"},
                                            {"id": "x", "effect": "allow"}]})
    with pytest.raises(PolicyError):
        validate_policy_document({"rules": [{"id": "x", "effect": "deny",
                                             "methods": ["FETCH"]}]})


def test_policy_file_load_cached_and_validated(tmp_path):
    path = tmp_path / "zt.json"
    path.write_text(json.dumps(POLICY))
    doc = load_policies(str(path))
    assert len(doc["rules"]) == 3
    bad = tmp_path / "zt-bad.json"
    bad.write_text('{"rules": [{"effect": "deny"}]}')  # missing id
    with pytest.raises(PolicyError):
        load_policies(str(bad))


def test_opa_adapter_decision_mapping():
    def stub_ok(method, url, headers, body, timeout):
        assert url.endswith("/v1/data/cryptoscan/allow")
        assert json.loads(body)["input"]["principal"] == "svc-1"
        return 200, json.dumps({"result": False})

    d = evaluate_opa("https://opa.internal:8181", "cryptoscan/allow",
                     principal="svc-1", roles=["scanner"], method="GET",
                     path="/api/v1/crypto/state", fetch=stub_ok)
    assert d["decision"] == "DENY" and d["engine"] == "opa"

    def stub_unreachable(method, url, headers, body, timeout):
        raise OSError("connection refused")

    with pytest.raises(PolicyError):
        evaluate_opa("https://opa.internal:8181", "cryptoscan/allow",
                     principal="svc-1", roles=[], method="GET", path="/x",
                     fetch=stub_unreachable)


def test_composed_decision_fail_closed_when_enforced():
    decision = zero_trust_decision(
        principal="svc-1", roles=["scanner"], method="GET",
        path="/api/v1/crypto/state", policy_file="", opa_url="https://opa.down:8181",
        enforced=True)
    assert decision["decision"] == "DENY"
    assert "fail-closed" in decision.get("reason", "")
    # not enforced: the failure is surfaced, not converted to a deny
    decision = zero_trust_decision(
        principal="svc-1", roles=["scanner"], method="GET",
        path="/api/v1/crypto/state", policy_file="", opa_url="https://opa.down:8181",
        enforced=False)
    assert decision["decision"] == "NOT_APPLICABLE"
    assert decision["errors"]


# ── API surfaces end to end ──────────────────────────────────────────

from fastapi.testclient import TestClient  # noqa: E402

from api.config.settings import get_settings  # noqa: E402


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/site.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("LICENSE_SIGNING_KEY", KEY)
    monkeypatch.setenv("LICENSE_DOCUMENT", json.dumps(_license()))
    monkeypatch.setenv("LICENSE_SITE_ID", "site-001")
    monkeypatch.setenv("LICENSE_REQUIRED", "true")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client


def test_site_security_endpoints(sqlite_app):
    client = sqlite_app

    # unauthenticated → 401 (before login primes cookies)
    assert client.get("/api/v1/license/status").status_code == 401

    login = client.post("/api/v1/auth/login",
                        json={"username": "admin", "password": "cryptoscan"})
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['token']}"}

    # license status: valid, and never echoes key or raw document
    r = client.get("/api/v1/license/status", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True and body["enforced"] is True
    assert body["plan"] == "AIRGAP" and body["site_id"] == "site-001"
    assert KEY not in json.dumps(body)

    # admin-only trial issuance (works with the configured key)
    r = client.post("/api/v1/license/trial", headers=headers, json={"days": 7})
    assert r.status_code == 200
    trial = verify_license(r.json(), signing_key=KEY, site_id="site-001")
    assert trial["plan"] == "PROFESSIONAL" and trial["days_remaining"] <= 7

    # secrets status: references only, no values
    r = client.get("/api/v1/security/secrets/status", headers=headers)
    assert r.status_code == 200
    status = r.json()
    assert status["enabled"] is True
    assert {p["name"] for p in status["providers"]} >= {"env", "file", "vault"}

    # zero-trust dry-run: no policies configured → NOT_APPLICABLE
    r = client.post("/api/v1/security/zero-trust/evaluate", headers=headers,
                    json={"principal": "ana", "roles": ["viewer"],
                          "method": "POST", "path": "/api/v1/systems"})
    assert r.status_code == 200
    assert r.json()["decision"] == "NOT_APPLICABLE"
    assert r.json()["enforced"] is False
    assert "never bypasses RBAC" in r.json()["composition"]

    r = client.get("/api/v1/security/zero-trust/policies", headers=headers)
    assert r.status_code == 200 and r.json()["rules"] == []


def test_zero_trust_middleware_enforces_deny(monkeypatch, tmp_path):
    policy_file = tmp_path / "zt.json"
    policy_file.write_text(json.dumps(POLICY))
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/zt.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("ZERO_TRUST_ENFORCED", "true")
    monkeypatch.setenv("ZERO_TRUST_POLICY_FILE", str(policy_file))
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        # unauthenticated request is denied by the PDP too (anonymous
        # principal, no roles — the viewer rule needs roles, the svc rule
        # needs the principal; anonymous POST matches no rule → allowed
        # through to the auth gate which 401s)
        assert client.get("/api/v1/systems").status_code == 401

        login = client.post("/api/v1/auth/login",
                            json={"username": "admin", "password": "cryptoscan"})
        headers = {"Authorization": f"Bearer {login.json()['token']}"}

        # policies surface shows the active document
        r = client.get("/api/v1/security/zero-trust/policies", headers=headers)
        assert r.status_code == 200
        assert r.json()["enforced"] is True
        assert len(r.json()["rules"]) == 3

        # dry-run: a viewer mutation is denied by rule
        r = client.post("/api/v1/security/zero-trust/evaluate", headers=headers,
                        json={"principal": "ana", "roles": ["viewer"],
                              "method": "DELETE", "path": "/api/v1/systems/x"})
        assert r.json()["decision"] == "DENY"
        assert r.json()["matched_rules"] == ["no-mutations-for-viewers"]

        # enforcement lives INSIDE the auth gate: admins still get RBAC
        # responses (the deny rules target other subjects)
        r = client.get("/api/v1/systems", headers=headers)
        assert r.status_code == 200


def test_license_required_gates_routes(monkeypatch, tmp_path):
    """require_license composes with RBAC: invalid license → 403."""
    from api.config.settings import get_settings as _gs

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/lic.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("LICENSE_SIGNING_KEY", KEY)
    monkeypatch.setenv("LICENSE_DOCUMENT", json.dumps({"license": {"format": "bogus"}}))
    monkeypatch.setenv("LICENSE_REQUIRED", "true")
    _gs.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.security.license import require_license

    # a gated route: register a probe dependency behavior directly
    dep = require_license(feature="scanning")
    try:
        dep()
        raised = None
    except Exception as exc:  # HTTPException
        raised = exc
    assert raised is not None and raised.status_code == 403
    assert raised.detail["code"] == "MALFORMED"
