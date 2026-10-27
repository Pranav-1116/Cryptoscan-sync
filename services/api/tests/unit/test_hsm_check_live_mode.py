"""/api/v1/crypto-assurance/hsm-check — submitted vs live verification.

The distinction is the point of these tests. In submitted mode the caller
posts the provider's own answer, so the verdict attests only to what was
reported. Live mode queries the provider through a real adapter; because that
needs outbound credentials it must stay opt-in, and the response must say
which mode produced the verdict so downstream evidence cannot conflate them.

Backed by a real in-memory SQLite session (the pattern in test_access_review)
rather than the mocked-repository ``app`` fixture: this endpoint writes an
audit row, and the role gate reads the users table.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.models.base import Base

API = "/api/v1/crypto-assurance/hsm-check"

# require_roles() refuses a credential-less request even when get_current_user
# is overridden, by design -- so the client must still present a bearer token.
AUTH = {"Authorization": "Bearer test-session-token"}

CLOUDHSM_KEY = {
    "key_ref": "arn:aws:kms:eu-west-1:1:key/abc",
    "provider": "aws_kms",
    "describe": {"metadata": {"origin": "AWS_CLOUDHSM", "key_spec": "RSA_2048"}},
}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor-1"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    with TestClient(app) as c:
        yield c
    session.close()
    engine.dispose()


def test_submitted_mode_is_labelled_submitted(client):
    r = client.post(API, json={"keys": [CLOUDHSM_KEY]}, headers=AUTH)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["verification_mode"] == "SUBMITTED"
    assert body["results"][0]["verification_mode"] == "SUBMITTED"
    assert body["results"][0]["hardware_backed"] is True


def test_live_mode_is_refused_unless_explicitly_enabled(client, monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_HSM_LIVE", raising=False)
    r = client.post(API, json={"keys": [CLOUDHSM_KEY], "live": True}, headers=AUTH)
    assert r.status_code == 403
    assert "CRYPTOSCAN_HSM_LIVE" in r.json()["detail"]


def test_live_mode_rejects_a_provider_with_no_adapter(client, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_HSM_LIVE", "true")
    r = client.post(
        API,
        json={"keys": [{"key_ref": "k", "provider": "not_a_provider"}], "live": True},
        headers=AUTH,
    )
    assert r.status_code == 400
    assert "no live adapter" in r.json()["detail"]


def test_live_mode_surfaces_a_connectivity_failure_as_a_result(client, monkeypatch):
    """A provider we cannot reach is a reported FAIL, never a silent pass."""
    monkeypatch.setenv("CRYPTOSCAN_HSM_LIVE", "true")
    r = client.post(
        API,
        json={
            "keys": [{
                "key_ref": "arn:aws:kms:eu-west-1:1:key/abc",
                "provider": "aws_kms",
                # No credentials here: the adapter is built, the describe call
                # fails, and check_key records that as a connectivity failure.
                "options": {"region": "eu-west-1"},
            }],
            "live": True,
        },
        headers=AUTH,
    )
    assert r.status_code == 200, r.text
    result = r.json()["results"][0]
    assert result["verification_mode"] == "LIVE"
    assert result["connectivity"] == "FAIL"
    assert result["hardware_backed"] is False
