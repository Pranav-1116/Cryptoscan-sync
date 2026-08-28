"""GET /cloud/credentials/status: admin-only credential diagnostics, no secrets."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user, require_admin
from api.main import create_app


@pytest.fixture()
def app_admin():
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"
    application.dependency_overrides[require_admin] = lambda: "auditor-not-admin"
    return application


@pytest.mark.asyncio
async def test_credentials_status_requires_admin_role(app_admin, monkeypatch):
    # drop the admin override so the real role gate applies
    app_admin.dependency_overrides.pop(require_admin)
    transport = ASGITransport(app=app_admin)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        anonymous = await client.get("/api/v1/cloud/credentials/status")
    assert anonymous.status_code in {401, 403}


@pytest.mark.asyncio
async def test_credentials_status_reports_sources_without_secrets(app_admin, monkeypatch):
    app_admin.dependency_overrides[require_admin] = lambda: "admin"
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATOPSECRET")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "TOPSECRETVALUE")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-central-1")
    transport = ASGITransport(app=app_admin)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/cloud/credentials/status")
    assert response.status_code == 200
    body = response.json()
    providers = {row["provider"]: row for row in body["providers"]}
    assert providers["aws"]["effective_source"] == "env-static-keys"
    assert providers["aws"]["region_hint"] == "eu-central-1"
    assert any("static keys" in warning for warning in providers["aws"]["warnings"])
    assert "aws" in body["configured"]
    assert any("no network calls" in note for note in body["notes"])
    rendered = repr(body)
    assert "AKIATOPSECRET" not in rendered and "TOPSECRETVALUE" not in rendered
