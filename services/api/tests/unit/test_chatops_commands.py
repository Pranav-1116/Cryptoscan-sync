"""Inbound ChatOps slash commands (deep/31, round 38)."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings

SECRET = "chatops-command-secret-0123456789"


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/chatops.db")
    monkeypatch.setenv("NEO4J_URI", "")
    monkeypatch.setenv("ALERT_CHATOPS_SECRET", SECRET)
    monkeypatch.setenv("ALERT_CHATOPS_COMMAND_TOKEN", "cmd-token-1")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/chatops.db"


def _post(client, text, *, token="cmd-token-1", secret=SECRET):
    # sign the exact bytes we send — the signature covers the raw body,
    # so the test must not let the client re-serialize it
    raw = json.dumps({"text": text, "token": token}).encode()
    digest = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return client.post("/api/v1/chatops/command", content=raw, headers={
        "Content-Type": "application/json",
        "X-CryptoScan-Signature": f"sha256={digest}",
    })


def test_help_and_unknown_commands(sqlite_app):
    client, _ = sqlite_app
    r = _post(client, "")
    assert r.status_code == 200 and "status" in r.json()["text"]
    r = _post(client, "destroy everything")
    assert r.status_code == 200 and "unknown command" in r.json()["text"]


def test_signature_and_token_are_the_credentials(sqlite_app, monkeypatch):
    client, _ = sqlite_app
    # wrong signature -> 401, never a partial answer
    r = _post(client, "status", secret="wrong-secret-entirely")
    assert r.status_code == 401
    # right signature, wrong token -> 401
    r = _post(client, "status", token="nope")
    assert r.status_code == 401
    # no secret configured at all -> 503, not an open surface
    monkeypatch.setenv("ALERT_CHATOPS_SECRET", "")
    get_settings.cache_clear()
    r = _post(client, "status", secret="")
    assert r.status_code == 503


def test_status_and_fact_and_advisories_read_only(sqlite_app):
    client, db_url = sqlite_app
    from datetime import datetime, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.cryptographic_fact import CryptographicFact
    from db.models.crypto_asset import CryptoAsset
    from db.models.threat_advisory import AlgorithmAdvisory

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    session.add(CryptoAsset(algorithm="RSA-2048", key_size=2048,
                            file_path="src/Keys.java", line_number=1,
                            confidence="HIGH"))
    session.add(CryptographicFact(algorithm="RSA-2048", purpose="ENCRYPTION",
                                  file_path="src/Keys.java",
                                  observation_count=7, scanners=["ast"],
                                  evidence_ids=[], confidences=["HIGH"]))
    session.add(AlgorithmAdvisory(
        advisory_id="SITE-001", source="central", advisory_type="DEPRECATION",
        algorithm="RSA-2048", severity="HIGH", title="RSA-2048 deprecation",
        published_at=datetime(2026, 9, 1, tzinfo=timezone.utc)))
    session.commit()
    session.close()
    eng.dispose()

    r = _post(client, "status")
    assert r.status_code == 200
    assert "1 crypto assets" in r.json()["text"]

    r = _post(client, "fact RSA-2048")
    text = r.json()["text"]
    assert "7 observation(s)" in text and "src/Keys.java" in text

    r = _post(client, "fact AES-256")
    assert "no facts recorded" in r.json()["text"]

    r = _post(client, "advisories RSA-2048")
    assert "SITE-001" in r.json()["text"] and "RSA-2048 deprecation" in r.json()["text"]

    r = _post(client, "advisories")
    assert "usage:" in r.json()["text"]


def test_form_encoded_slack_payloads_work_too(sqlite_app):
    client, _ = sqlite_app
    raw = b"text=status&token=cmd-token-1"
    digest = hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    r = client.post("/api/v1/chatops/command", content=raw, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CryptoScan-Signature": f"sha256={digest}",
    })
    assert r.status_code == 200
    assert "estate" in r.json()["text"]
