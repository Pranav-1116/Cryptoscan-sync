"""Lifecycle timeline derived from the audited event trail (advanced/54 P0#4, round 32)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register all tables
from api.config.settings import get_settings


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/lifecycle.db"
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
        yield client, db_url


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _seed_asset(db_url, asset_id, algorithm="3DES"):
    eng = create_engine(db_url)
    Session = sessionmaker(bind=eng)
    session = Session()
    from db.models.crypto_asset import CryptoAsset

    session.add(CryptoAsset(id=asset_id, algorithm=algorithm, file_path="/app/legacy.py",
                            line_number=42, confidence="HIGH"))
    session.commit()
    session.close()
    eng.dispose()


def test_timeline_derived_from_transition_trail(sqlite_app):
    client, db_url = sqlite_app
    _seed_asset(db_url, "asset-tl-1")
    admin = _login(client)

    # no transitions yet: empty trail, all derived timestamps honestly null
    r = client.get("/api/v1/inventory/assets/asset-tl-1/lifecycle/timeline",
                   headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "lifecycle-timeline/derived-v1"
    assert body["current_state"] == "DISCOVERED"
    assert body["transition_count"] == 0
    assert set(body["derived_timestamps"].values()) == {None}

    # walk DISCOVERED -> VERIFIED -> ACTIVE
    for to_state in ("VERIFIED", "ACTIVE"):
        r = client.post("/api/v1/inventory/assets/asset-tl-1/lifecycle",
                        json={"to_state": to_state, "reason": f"testing {to_state}"},
                        headers=admin)
        assert r.status_code == 200, r.text

    r = client.get("/api/v1/inventory/assets/asset-tl-1/lifecycle/timeline",
                   headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current_state"] == "ACTIVE"
    assert body["transition_count"] == 2
    assert [t["to_state"] for t in body["transitions"]] == ["VERIFIED", "ACTIVE"]
    assert all(t["reason"] for t in body["transitions"])
    assert all(t["actor"] == "admin" for t in body["transitions"])
    assert all(t["at"] for t in body["transitions"])
    derived = body["derived_timestamps"]
    assert derived["verified_at"] is not None
    assert derived["active_at"] is not None
    assert derived["deprecated_at"] is None and derived["retired_at"] is None

    # deprecate -> derived deprecated_at appears; active_at keeps its first stamp
    r = client.post("/api/v1/inventory/assets/asset-tl-1/lifecycle",
                    json={"to_state": "DEPRECATED", "reason": "sunset"},
                    headers=admin)
    assert r.status_code == 200, r.text
    body = client.get("/api/v1/inventory/assets/asset-tl-1/lifecycle/timeline",
                      headers=admin).json()
    assert body["derived_timestamps"]["deprecated_at"] is not None
    assert body["transition_count"] == 3

    # the trail is per-asset: another asset's timeline stays empty
    _seed_asset(db_url, "asset-tl-2", algorithm="RC4")
    other = client.get("/api/v1/inventory/assets/asset-tl-2/lifecycle/timeline",
                       headers=admin).json()
    assert other["transition_count"] == 0


def test_timeline_unknown_asset_404_and_anon_401(sqlite_app):
    client, _ = sqlite_app
    r = client.get("/api/v1/inventory/assets/missing/lifecycle/timeline")
    assert r.status_code == 401

    admin = _login(client)
    r = client.get("/api/v1/inventory/assets/missing/lifecycle/timeline",
                   headers=admin)
    assert r.status_code == 404
