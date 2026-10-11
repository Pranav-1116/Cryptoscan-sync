"""Field-level audit diffs (advanced/78 P0#1, round 32).

Pure diff helper + the three audited identity-plane mutation surfaces that
now carry before/after per changed field.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings
from api.security.audit_diff import audit_detail_with_changes, field_diff


# ── pure helper ───────────────────────────────────────────────────────


def test_field_diff_lists_only_changed_fields():
    diff = field_diff(
        {"roles": ["viewer"], "is_active": True, "email": "x@y.z"},
        {"roles": ["auditor", "viewer"], "is_active": True, "email": "x@y.z"},
    )
    assert [c["field"] for c in diff] == ["roles"]
    assert diff[0]["before"] == ["viewer"]
    assert diff[0]["after"] == ["auditor", "viewer"]


def test_field_diff_masks_sensitive_values():
    diff = field_diff({"password": "hunter2"}, {"password": "n3w!secret"})
    assert diff == [{"field": "password", "before": "***", "after": "***"}]
    # sensitive even when the field only appears on one side
    diff = field_diff({}, {"api_key": "sk-live-123"})
    assert diff[0]["before"] is None and diff[0]["after"] == "***"


def test_field_diff_covers_new_and_removed_fields():
    diff = field_diff({"a": 1}, {"b": 2})
    fields = {c["field"]: c for c in diff}
    assert set(fields) == {"a", "b"}
    assert fields["a"]["before"] == 1 and fields["a"]["after"] is None
    assert fields["b"]["before"] is None and fields["b"]["after"] == 2


def test_audit_detail_carries_summary():
    detail = audit_detail_with_changes(
        field_diff({"is_active": True}, {"is_active": False}),
        password_rotated=True,
    )
    assert detail["summary"] == ["is_active"]
    assert detail["password_rotated"] is True
    assert detail["changes"][0]["after"] is False


# ── API surfaces ──────────────────────────────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/auditdiff.db"
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
        yield client


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _audit_events(client, action):
    r = client.get(f"/api/v1/auth/audit?action={action}", headers=_login(client))
    assert r.status_code == 200, r.text
    return r.json()["events"]


def test_user_update_audits_field_level_diff(sqlite_app):
    client = sqlite_app
    admin = _login(client)

    # create a plain user, then change roles + deactivate in one PATCH
    r = client.post("/api/v1/auth/users",
                    json={"username": "diffuser", "password": "Quv7#zLm2$pWx9",
                          "roles": ["viewer"]}, headers=admin)
    assert r.status_code == 201, r.text

    r = client.patch("/api/v1/auth/users/diffuser",
                     json={"roles": ["auditor"], "is_active": False},
                     headers=admin)
    assert r.status_code == 200, r.text

    events = _audit_events(client, "user.update")
    assert events, "user.update audit row missing"
    detail = events[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert changes["roles"]["before"] == ["viewer"]
    assert changes["roles"]["after"] == ["auditor"]
    assert changes["is_active"]["before"] is True
    assert changes["is_active"]["after"] is False
    assert detail["summary"] == ["is_active", "roles"]
    # deactivation revokes sessions — recorded, but not as a field change
    assert detail["revoked_sessions"] >= 0


def test_password_rotation_audits_masked_marker(sqlite_app):
    client = sqlite_app
    admin = _login(client)
    r = client.post("/api/v1/auth/users",
                    json={"username": "pwuser", "password": "Quv7#zLm2$pWx9",
                          "roles": ["viewer"]}, headers=admin)
    assert r.status_code == 201, r.text
    r = client.patch("/api/v1/auth/users/pwuser",
                     json={"password": "Rt5!kN8@wQd3"}, headers=admin)
    assert r.status_code == 200, r.text

    detail = _audit_events(client, "user.update")[0]["detail"]
    pw = next(c for c in detail["changes"] if c["field"] == "password")
    assert pw["before"] == "***" and pw["after"] == "***"
    assert detail["password_rotated"] is True
    # the rotation marker and the masked diff carry no actual secret
    assert "Rt5!kN8@wQd3" not in str(detail) and "Quv7#zLm2$pWx9" not in str(detail)


def test_custom_role_update_audits_field_level_diff(sqlite_app):
    client = sqlite_app
    admin = _login(client)
    r = client.post("/api/v1/auth/custom-roles",
                    json={"name": "diffrole", "permissions": ["crypto.read"],
                          "description": "before"}, headers=admin)
    assert r.status_code in (200, 201), r.text

    r = client.put("/api/v1/auth/custom-roles/diffrole",
                   json={"permissions": ["crypto.read", "reports.read"],
                         "description": "after"}, headers=admin)
    assert r.status_code == 200, r.text

    detail = _audit_events(client, "custom_role.update")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert changes["permissions"]["before"] == ["crypto.read"]
    assert changes["permissions"]["after"] == ["crypto.read", "reports.read"]
    assert changes["description"]["before"] == "before"
    assert changes["description"]["after"] == "after"


def test_profile_update_audits_field_level_diff(sqlite_app):
    client = sqlite_app
    r = client.patch("/api/v1/auth/me",
                     json={"display_name": "Changed Name"}, headers=_login(client))
    assert r.status_code == 200, r.text

    detail = _audit_events(client, "user.profile_update")[0]["detail"]
    changes = {c["field"]: c for c in detail["changes"]}
    assert "display_name" in changes
    assert changes["display_name"]["after"] == "Changed Name"
