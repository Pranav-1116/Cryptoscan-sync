"""Asset↔fact reconciliation (advanced/51 rearchitecture step, round 38)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings
from db.fact_projection import asset_fact_key, reconcile_assets_with_facts


# ── pure ─────────────────────────────────────────────────────────────


def _asset(algorithm, file_path, key_size=None, purpose=None, mode=None):
    return {"algorithm": algorithm, "file_path": file_path,
            "key_size": key_size, "purpose": purpose, "mode": mode}


def test_identity_spaces_match():
    asset = _asset("RSA-2048", "a.py", 2048, "ENCRYPTION", "CBC")
    assert asset_fact_key(asset) == (
        "RSA-2048", "ENCRYPTION", "a.py", 2048, "CBC")
    # ""-normalisation: None and "" are the same identity on both sides
    assert asset_fact_key(_asset("AES", "b.py")) == (
        "AES", "", "b.py", "", "")


def test_reconciliation_reports_in_sync_when_paths_agree():
    rows = [_asset("RSA-2048", "a.py", 2048, "ENCRYPTION"),
            _asset("AES-128", "b.py", 128, "ENCRYPTION")]
    result = reconcile_assets_with_facts(rows, rows)
    assert result["in_sync"] is True
    assert result["identities_matched"] == 2
    assert result["disagreement_count"] == 0


def test_reconciliation_reports_field_disagreements():
    assets = [_asset("RSA", "a.py", 2048, "ENCRYPTION")]
    facts = [_asset("RSA", "a.py", 1024, "SIGNING", "CBC")]
    result = reconcile_assets_with_facts(assets, facts)
    assert result["identities_matched"] == 1
    assert result["in_sync"] is False
    disagreement = result["field_disagreements"][0]
    assert disagreement["algorithm"] == "RSA"
    assert disagreement["fields"]["key_size"] == {"asset": ["2048"],
                                                  "fact": ["1024"]}
    assert disagreement["fields"]["purpose"] == {"asset": ["ENCRYPTION"],
                                                 "fact": ["SIGNING"]}
    assert disagreement["fields"]["mode"] == {"asset": [None], "fact": ["CBC"]}


def test_reconciliation_reports_one_sided_identities():
    assets = [_asset("RSA", "a.py"), _asset("SHA-1", "orphan-asset.py")]
    facts = [_asset("RSA", "a.py"), _asset("MD5", "orphan-fact.py")]
    result = reconcile_assets_with_facts(assets, facts)
    assert result["assets_without_facts"] == ["SHA-1@orphan-asset.py"]
    assert result["facts_without_assets"] == ["MD5@orphan-fact.py"]
    assert result["in_sync"] is False


def test_empty_inputs_are_in_sync_vacuously():
    result = reconcile_assets_with_facts([], [])
    assert result["in_sync"] is True
    assert result["model"] == "asset-fact/reconciliation-v1"


# ── API ──────────────────────────────────────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/rec.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/rec.db"


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_reconciliation_endpoint_measures_live_drift(sqlite_app):
    from datetime import datetime, timezone

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.crypto_asset import CryptoAsset
    from db.models.evidence_record import EvidenceRecord

    client, db_url = sqlite_app
    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    # the fused write path recorded RSA-2048/2048; the evidence says 1024
    session.add(CryptoAsset(algorithm="RSA-2048", key_size=2048,
                            purpose="ENCRYPTION", file_path="a.py",
                            line_number=1, confidence="HIGH"))
    session.add(EvidenceRecord(
        scan_id="s1", content_hash="1" * 64, chain_hash="0" * 64,
        chain_position=0, algorithm="RSA-2048", purpose="ENCRYPTION",
        key_size=1024, file_path="a.py", line_number=1,
        finding_data={"scanner_id": "ast"}, confidence="HIGH",
        compliance_status="FAIL",
        created_at=datetime(2026, 10, 1, tzinfo=timezone.utc)))
    session.commit()
    session.close()
    eng.dispose()

    r = client.get("/api/v1/facts/reconciliation")
    assert r.status_code == 401  # admin surface

    admin = _login(client)
    r = client.get("/api/v1/facts/reconciliation", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "asset-fact/reconciliation-v1"
    assert body["assets_indexed"] == 1
    assert body["facts_indexed"] == 0  # no rebuild yet: fact store empty
    assert body["assets_without_facts"] == ["RSA-2048@a.py"]
    assert body["in_sync"] is False
    assert "single-writer" in body["note"]

    # after a rebuild, the drift becomes a field disagreement (2048 vs 1024)
    r = client.post("/api/v1/facts/rebuild", headers=admin)
    assert r.status_code == 200
    r = client.get("/api/v1/facts/reconciliation", headers=admin)
    body = r.json()
    assert body["identities_matched"] == 1
    assert body["field_disagreements"][0]["fields"]["key_size"] == {
        "asset": ["2048"], "fact": ["1024"]}
