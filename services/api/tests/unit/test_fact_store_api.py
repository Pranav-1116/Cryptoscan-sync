"""Fact store API (advanced/51, round 35): rebuild + unchanged read contract."""

from __future__ import annotations

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
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/factstore.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/factstore.db"


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _seed(db_url):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.evidence_record import EvidenceRecord

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    for index, (algo, path, line) in enumerate([
        ("RSA-2048", "src/pay/Keys.java", 11),
        ("RSA-2048", "src/pay/Keys.java", 44),
        ("AES-128", "src/old/Legacy.java", 7),
    ]):
        session.add(EvidenceRecord(
            scan_id="scan-fs", content_hash=f"{index}" * 64,
            chain_hash=f"{index}" + "0" * 63, chain_position=index,
            algorithm=algo, purpose="ENCRYPTION", key_size=None,
            file_path=path, line_number=line,
            finding_data={"scanner_id": "ast"}, confidence="HIGH",
            compliance_status="FAIL",
        ))
    session.commit()
    session.close()
    eng.dispose()


def test_fact_store_rebuild_and_read_contract(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url)

    r = client.post("/api/v1/facts/rebuild")
    assert r.status_code == 401  # anon first

    admin = _login(client)
    r = client.post("/api/v1/facts/rebuild", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "fact-store/rebuild-v1"
    assert body["facts_upserted"] == 2 and body["evidence_rows"] == 3
    assert "rebuildable" in body["note"]

    # prefix-scoped rebuild touches only matching files
    r = client.post("/api/v1/facts/rebuild",
                    params={"file_prefix": "src/pay"}, headers=admin)
    assert r.status_code == 200
    assert r.json()["facts_upserted"] == 1 and r.json()["evidence_rows"] == 2

    # the live read projection keeps its round-31 contract, unchanged
    r = client.get("/api/v1/facts/crypto", headers=admin)
    assert r.status_code == 200, r.text
    facts = r.json()
    assert facts["model"] == "cryptographic-facts/read-projection-v1"
    assert facts["facts_matching"] == 2
    assert "live" in facts["note"]

    # and the fact table agrees with the projection
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker

    from db.models.cryptographic_fact import CryptographicFact

    eng = create_engine(db_url)
    rows = list(sessionmaker(bind=eng)().execute(select(CryptographicFact)).scalars())
    eng.dispose()
    assert sorted(r.algorithm for r in rows) == ["AES-128", "RSA-2048"]
    assert all(r.is_current for r in rows)


def test_fact_store_rebuild_empty_is_empty(sqlite_app):
    client, _ = sqlite_app
    admin = _login(client)
    r = client.post("/api/v1/facts/rebuild", headers=admin)
    assert r.status_code == 200
    assert r.json()["facts_upserted"] == 0 and r.json()["evidence_rows"] == 0
