"""Fact store read path (advanced/51 P0#1, round 37)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/fsr.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/fsr.db"


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _seed(db_url, scan="scan-1", when=None):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.evidence_record import EvidenceRecord

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    stamp = when or datetime(2026, 10, 1, tzinfo=timezone.utc)
    for index, (algo, path, line, confidence) in enumerate([
        ("RSA-2048", "src/pay/Keys.java", 11, "HIGH"),
        ("RSA-2048", "src/pay/Keys.java", 44, "MEDIUM"),
        ("AES-128", "src/old/Legacy.java", 7, "HIGH"),
    ]):
        session.add(EvidenceRecord(
            scan_id=scan, content_hash=f"{index}" * 64,
            chain_hash=f"{index}" + "0" * 63, chain_position=index,
            algorithm=algo, purpose="ENCRYPTION", key_size=None,
            file_path=path, line_number=line,
            finding_data={"scanner_id": "ast"}, confidence=confidence,
            compliance_status="FAIL", created_at=stamp,
        ))
    session.commit()
    session.close()
    eng.dispose()


def _rebuild(client, admin):
    r = client.post("/api/v1/facts/rebuild", headers=admin)
    assert r.status_code == 200, r.text
    return r.json()


def test_store_read_matches_live_projection_exactly(sqlite_app):
    """The 51 equivalence pin: store rows == live-projected facts."""
    client, db_url = sqlite_app
    _seed(db_url)
    admin = _login(client)
    _rebuild(client, admin)

    live = client.get("/api/v1/facts/crypto", headers=admin).json()
    store = client.get("/api/v1/facts/store", headers=admin).json()

    assert store["model"] == "fact-store/read-v1"
    assert store["freshness"] == "current"
    assert store["stale_rows"] == 0
    assert store["summary"] == live["summary"]
    assert store["facts_matching"] == live["facts_matching"] == 2
    # identical fact lists modulo the store's one addition: `fresh`.
    # Same shape, same order — a client can switch endpoints without
    # reshaping.
    stripped = [{k: v for k, v in f.items() if k != "fresh"}
                for f in store["facts"]]
    assert stripped == live["facts"]
    # the store carries the projection's confidences now
    rsa = next(f for f in store["facts"]
               if f["fact"]["algorithm"] == "RSA-2048")
    assert rsa["confidences"] == ["HIGH", "MEDIUM"]
    assert rsa["fresh"] is True


def test_store_reports_stale_when_evidence_is_newer(sqlite_app, monkeypatch):
    import db.repositories.fact_repository as fr_mod

    client, db_url = sqlite_app
    _seed(db_url)  # evidence created 2026-10-01
    admin = _login(client)

    rebuild_clock = datetime(2026, 10, 10, tzinfo=timezone.utc)

    class _Clock(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: A003 — mirrors datetime.now
            return rebuild_clock

    monkeypatch.setattr(fr_mod, "datetime", _Clock)
    _rebuild(client, admin)  # rebuild stamped 2026-10-10

    # evidence arrives AFTER the rebuild — the store must say so
    _seed(db_url, scan="scan-2",
          when=datetime(2026, 10, 11, tzinfo=timezone.utc))
    store = client.get("/api/v1/facts/store", headers=admin).json()
    assert store["freshness"] == "stale"
    assert store["stale_rows"] >= 1
    stale = [f for f in store["facts"] if not f["fresh"]]
    assert any(f["fact"]["algorithm"] == "RSA-2048" for f in stale)

    # a later rebuild covers the new evidence -> current again
    rebuild_clock = datetime(2026, 10, 12, tzinfo=timezone.utc)
    _rebuild(client, admin)
    store = client.get("/api/v1/facts/store", headers=admin).json()
    assert store["freshness"] == "current"
    assert store["stale_rows"] == 0
    assert store["facts_matching"] == 2  # scan-2 fed the SAME facts


def test_store_filters_and_empty_honesty(sqlite_app):
    client, db_url = sqlite_app
    admin = _login(client)
    # nothing seeded, nothing rebuilt: empty, not silently current
    store = client.get("/api/v1/facts/store", headers=admin).json()
    assert store["freshness"] == "empty"
    assert store["facts"] == []

    _seed(db_url)
    _rebuild(client, admin)
    store = client.get("/api/v1/facts/store", headers=admin,
                       params={"file_prefix": "src/pay"}).json()
    assert [f["fact"]["algorithm"] for f in store["facts"]] == ["RSA-2048"]
    store = client.get("/api/v1/facts/store", headers=admin,
                       params={"algorithm": "AES-128",
                               "min_observations": 2}).json()
    assert store["facts"] == []  # AES has one observation


def test_store_requires_auth(sqlite_app):
    client, _ = sqlite_app
    assert client.get("/api/v1/facts/store").status_code == 401
