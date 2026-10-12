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


def test_prefix_rebuild_retires_fact_after_last_evidence_is_retracted(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url)
    admin = _login(client)
    assert client.post("/api/v1/facts/rebuild", headers=admin).status_code == 200

    from datetime import datetime, timezone

    from sqlalchemy import create_engine, update

    from db.models.evidence_record import EvidenceRecord

    eng = create_engine(db_url)
    with eng.begin() as connection:
        connection.execute(update(EvidenceRecord).where(
            EvidenceRecord.file_path == "src/old/Legacy.java"
        ).values(deleted_at=datetime.now(timezone.utc)))
    eng.dispose()

    r = client.post("/api/v1/facts/rebuild", params={"file_prefix": "src/old"},
                    headers=admin)
    assert r.status_code == 200, r.text
    assert r.json()["facts_stale"] == 1
    r = client.get("/api/v1/facts/store", headers=admin)
    assert r.status_code == 200
    assert {f["fact"]["algorithm"] for f in r.json()["facts"]} == {"RSA-2048"}


def test_fact_store_counts_all_matches_beyond_page_and_summarizes_page_only(sqlite_app):
    client, db_url = sqlite_app
    admin = _login(client)

    from datetime import datetime, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from db.models.cryptographic_fact import CryptographicFact

    eng = create_engine(db_url)
    with sessionmaker(bind=eng)() as session:
        session.add_all([
            CryptographicFact(algorithm="RSA", tenant_id=None, purpose="",
                              file_path=f"src/%_literal/{i:04d}.py", mode="",
                              observation_count=2,
                              rebuilt_at=datetime.now(timezone.utc))
            for i in range(1005)
        ])
        session.add(CryptographicFact(
            algorithm="AES", tenant_id=None, purpose="",
            file_path="src/XXliteral/not-a-match.py", mode="",
            observation_count=3,
        ))
        session.commit()
    eng.dispose()

    response = client.get("/api/v1/facts/store", headers=admin, params={
        "algorithm": "RSA", "file_prefix": "src/%_literal/",
        "min_observations": 2, "limit": 1000,
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["facts_matching"] == 1005
    assert body["facts_returned"] == len(body["facts"]) == 1000
    assert body["truncated"] is True
    assert body["summary_scope"] == "returned_page"
    assert body["summary"]["facts_total"] == 1000
    assert body["summary"]["observations_total"] == 2000
    assert body["facts"][0]["fact"]["file_path"].endswith("0000.py")
    assert body["facts"][-1]["fact"]["file_path"].endswith("0999.py")
    assert body["offset"] == 0 and body["next_offset"] == 1000

    remainder_response = client.get("/api/v1/facts/store", headers=admin, params={
        "algorithm": "RSA", "file_prefix": "src/%_literal/",
        "min_observations": 2, "limit": 1000, "offset": body["next_offset"],
    })
    assert remainder_response.status_code == 200, remainder_response.text
    remainder = remainder_response.json()
    assert remainder["facts_matching"] == 1005
    assert remainder["offset"] == 1000
    assert remainder["facts_returned"] == 5
    assert remainder["facts"][0]["fact"]["file_path"].endswith("1000.py")
    assert remainder["facts"][-1]["fact"]["file_path"].endswith("1004.py")
    assert remainder["summary"]["facts_total"] == 5
    assert remainder["truncated"] is False and remainder["next_offset"] is None

    page = client.get("/api/v1/facts/store", headers=admin, params={
        "algorithm": "RSA", "file_prefix": "src/%_literal/", "limit": 5,
    }).json()
    assert page["facts_matching"] == 1005
    assert page["facts_returned"] == page["summary"]["facts_total"] == 5
    assert page["truncated"] is True
    assert client.get("/api/v1/facts/store", headers=admin,
                      params={"offset": -1}).status_code == 422


def test_fact_store_rebuild_empty_is_empty(sqlite_app):
    client, _ = sqlite_app
    admin = _login(client)
    r = client.post("/api/v1/facts/rebuild", headers=admin)
    assert r.status_code == 200
    assert r.json()["facts_upserted"] == 0 and r.json()["evidence_rows"] == 0
