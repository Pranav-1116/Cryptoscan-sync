"""Unified BOM query layer (advanced/46, round 37)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings
from cbom.bom_query import query_boms


def _boms():
    return {
        "cbom": {"components": [
            {"type": "cryptographic-asset", "name": "RSA 2048", "bom-ref": "c1",
             "cryptoProperties": {"algorithmProperties": {
                 "algorithm": "RSA-2048", "parameterSetIdentifier": "2048"}}},
            {"type": "cryptographic-asset", "name": "AES 256", "bom-ref": "c2",
             "cryptoProperties": {"algorithmProperties": {
                 "algorithm": "AES-256", "parameterSetIdentifier": "256"}}},
            {"type": "application", "name": "Payment API", "bom-ref": "c3"},
        ]},
        "techbom": {"layers": {
            "cbom": {"components": [
                {"type": "crypto", "algorithm": "RSA-2048", "key_size": 1024,
                 "bom-ref": "t1"},
                {"type": "crypto", "algorithm": "SHA-1", "bom-ref": "t2"},
            ]},
            "sbom": {"components": [
                {"type": "application", "name": "payment api", "bom-ref": "t3"},
            ]},
        }},
        "vbom": {"components": [
            {"type": "vendor", "name": "Thales", "bom-ref": "v1",
             "risk_level": "HIGH"},
        ]},
    }


def test_query_by_identity_returns_the_full_dossier():
    result = query_boms(_boms(), identity="crypto:RSA-2048")
    assert result["identities_matching"] == 1
    match = result["matches"][0]
    assert match["linked"] is True
    assert match["bom_count"] == 2
    refs = {entry["bom"]: entry["ref"] for entry in match["present_in"]}
    assert refs == {"cbom": "c1", "techbom": "t1"}
    # the disagreement is right there with the values that produced it
    conflict = match["conflicts"][0]
    assert conflict["field"] == "key size"
    values = {v["bom"]: v["value"] for v in conflict["values"]}
    assert values == {"cbom": "2048", "techbom": "1024"}


def test_kind_and_algorithm_filters():
    crypto = query_boms(_boms(), kind="crypto")
    assert {m["identity"] for m in crypto["matches"]} == {
        "crypto:RSA-2048", "crypto:AES-256", "crypto:SHA-1"}
    aes = query_boms(_boms(), algorithm="aes 256")  # survives spacing
    assert [m["identity"] for m in aes["matches"]] == ["crypto:AES-256"]
    vendors = query_boms(_boms(), kind="vendor")
    assert [m["label"] for m in vendors["matches"]] == ["Thales"]


def test_linked_unlinked_and_coverage_gaps():
    result = query_boms(_boms(), unlinked_only=True)
    identities = {m["identity"] for m in result["matches"]}
    # AES-256, SHA-1 (crypto in one BOM each) and Thales (vendor only)
    assert identities == {"crypto:AES-256", "crypto:SHA-1", "vendor:thales"}
    linked = query_boms(_boms(), linked_only=True)
    assert {m["identity"] for m in linked["matches"]} == {
        "crypto:RSA-2048", "application:payment api"}


def test_bom_filter_and_unknown_bom_error():
    result = query_boms(_boms(), bom="vbom")
    assert {m["identity"] for m in result["matches"]} == {"vendor:thales"}
    result = query_boms(_boms(), bom="nbom")
    assert result["matches"] == []
    assert "unknown BOM" in result["error"]


def test_conflicts_only():
    result = query_boms(_boms(), conflicts_only=True)
    assert result["conflict_count"] >= 1
    assert all(m["conflicts"] for m in result["matches"])
    assert [m["identity"] for m in result["matches"]] == ["crypto:RSA-2048"]


def test_empty_inputs_answer_cleanly():
    result = query_boms({})
    assert result["identities_total"] == 0
    assert result["matches"] == []
    result = query_boms({"cbom": {}})
    assert result["identities_matching"] == 0


def test_query_echoes_its_own_parameters():
    result = query_boms(_boms(), kind="crypto", linked_only=True)
    assert result["query"] == {
        "identity": None, "kind": "crypto", "bom": None, "algorithm": None,
        "linked_only": True, "unlinked_only": False, "conflicts_only": False,
    }


# ── API end to end ───────────────────────────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/bomq.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/bomq.db"


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_query_endpoint_over_live_inventory(sqlite_app):
    client, db_url = sqlite_app
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.crypto_asset import CryptoAsset

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    session.add(CryptoAsset(algorithm="RSA-2048", key_size=2048,
                            purpose="ENCRYPTION", file_path="a.py",
                            line_number=1, confidence="HIGH"))
    session.commit()
    session.close()
    eng.dispose()

    r = client.get("/api/v1/cbom/query")
    assert r.status_code == 401

    admin = _login(client)
    r = client.get("/api/v1/cbom/query", headers=admin,
                   params={"identity": "crypto:RSA-2048"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "cross-bom/query-v1"
    assert body["identities_matching"] == 1
    assert body["matches"][0]["bom_count"] == 2
    assert body["live"] is True

    # filters work end to end too
    r = client.get("/api/v1/cbom/query", headers=admin,
                   params={"kind": "crypto", "unlinked_only": "true"})
    assert r.status_code == 200
    assert r.json()["identities_matching"] == 0  # RSA is linked
