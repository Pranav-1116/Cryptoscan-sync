"""Cryptographic fact projection (advanced/48 + 51 P0#1, round 31)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.facts.projection import fact_key, project_facts, summarize_facts


def _row(algorithm, path, line=1, purpose="ENCRYPTION", key_size=None, mode=None,
         confidence="HIGH", scanner="ast-scanner", created=None, deleted=None):
    return {
        "id": f"ev-{algorithm}-{path}-{line}".replace("/", "_"),
        "algorithm": algorithm,
        "purpose": purpose,
        "file_path": path,
        "line_number": line,
        "key_size": key_size,
        "mode": mode,
        "confidence": confidence,
        "is_hardcoded_key": False,
        "finding_data": {"scanner_id": scanner},
        "created_at": created or datetime(2026, 10, 1, tzinfo=timezone.utc),
    }


# ── pure projection ──────────────────────────────────────────────────


def test_fact_identity_groups_same_fact_across_lines_and_scans():
    rows = [
        _row("AES-256", "src/pay/Cipher.java", line=10, key_size=256, mode="GCM",
             created=datetime(2026, 9, 1, tzinfo=timezone.utc)),
        _row("AES-256", "src/pay/Cipher.java", line=42, key_size=256, mode="GCM",
             scanner="regex-scanner", confidence="MEDIUM",
             created=datetime(2026, 10, 5, tzinfo=timezone.utc)),
        _row("AES-256", "src/pay/Cipher.java", line=99, key_size=256, mode="GCM"),
    ]
    facts = project_facts(rows)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["observation_count"] == 3
    assert fact["scanners"] == ["ast-scanner", "regex-scanner"]
    assert fact["confidences"] == ["HIGH", "MEDIUM"]
    assert fact["first_seen"].startswith("2026-09-01")
    assert fact["last_seen"].startswith("2026-10-05")
    assert fact["evidence_count"] == 3 and not fact["evidence_truncated"]
    # different parameters → different facts
    facts2 = project_facts(rows + [_row("AES-256", "src/pay/Cipher.java", key_size=128, mode="GCM")])
    assert len(facts2) == 2
    # different file → different fact (location is part of identity)
    facts3 = project_facts(rows + [_row("AES-256", "src/other/Cipher.java", key_size=256, mode="GCM")])
    assert len(facts3) == 2


def test_fact_key_and_truncation_and_summary():
    assert fact_key(_row("RSA", "a.java", key_size=2048)) == ("RSA", "ENCRYPTION", "a.java", 2048, "")
    rows = [_row("RSA", "f.java", line=i) for i in range(60)]
    rows[0]["is_hardcoded_key"] = True
    facts = project_facts(rows, max_evidence_refs=10)
    assert facts[0]["evidence_count"] == 60
    assert len(facts[0]["evidence_ids"]) == 10
    assert facts[0]["evidence_truncated"] is True
    summary = summarize_facts(facts)
    assert summary["facts_total"] == 1
    assert summary["observations_total"] == 60
    assert summary["facts_with_hardcoded_keys"] == 1
    assert summary["facts_by_algorithm"] == {"RSA": 1}


# ── API end to end ───────────────────────────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/facts.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/facts.db"


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_facts_api_over_seeded_evidence(sqlite_app):
    client, db_url = sqlite_app
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.evidence_record import EvidenceRecord

    eng = create_engine(db_url)
    Session = sessionmaker(bind=eng)
    session = Session()
    for index, (algo, path, line, size) in enumerate([
        ("RSA-2048", "src/pay/Keys.java", 11, 2048),
        ("RSA-2048", "src/pay/Keys.java", 44, 2048),
        ("AES-128", "src/old/Legacy.java", 7, 128),
        ("SHA-1", "src/hash/Digest.java", 3, None),
    ]):
        session.add(EvidenceRecord(
            scan_id="scan-facts", content_hash=f"{index}" * 64,
            chain_hash=f"{index}" + "0" * 63, chain_position=index,
            algorithm=algo, purpose="ENCRYPTION" if algo.startswith(("RSA", "AES")) else "HASHING",
            key_size=size, file_path=path, line_number=line,
            finding_data={"scanner_id": "ast-scanner"}, confidence="HIGH",
            compliance_status="FAIL" if algo in ("AES-128", "SHA-1") else "PASS",
        ))
    session.commit()
    session.close()
    eng.dispose()

    # unauthenticated rejected (before login primes cookies)
    assert client.get("/api/v1/facts/crypto").status_code == 401

    headers = _login(client)

    r = client.get("/api/v1/facts/crypto", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "cryptographic-facts/read-projection-v1"
    assert body["evidence_rows_read"] == 4
    # RSA-2048 twice in one file folds to ONE fact with 2 observations
    summary = body["summary"]
    assert summary["facts_total"] == 3
    assert summary["observations_total"] == 4
    assert summary["facts_by_algorithm"]["RSA-2048"] == 1
    rsa_fact = [f for f in body["facts"] if f["fact"]["algorithm"] == "RSA-2048"][0]
    assert rsa_fact["observation_count"] == 2
    assert rsa_fact["evidence_count"] == 2

    # filters
    r = client.get("/api/v1/facts/crypto", headers=headers,
                   params={"algorithm": "SHA-1"})
    assert r.json()["summary"]["facts_total"] == 1
    r = client.get("/api/v1/facts/crypto", headers=headers,
                   params={"file_prefix": "src/pay"})
    assert r.json()["summary"]["facts_total"] == 1  # only Keys.java
    r = client.get("/api/v1/facts/crypto", headers=headers,
                   params={"min_observations": 2})
    assert r.json()["summary"]["facts_total"] == 1  # only the RSA fact

