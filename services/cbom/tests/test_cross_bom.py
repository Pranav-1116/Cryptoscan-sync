"""Cross-BOM linking and conflict detection (advanced/46, round 36)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings
from cbom.cross_bom import canonical_identity, cross_boms, index_bom


# ── pure: canonical identity ─────────────────────────────────────────


def test_crypto_identity_normalizes_algorithm_names():
    techbom_row = {"type": "crypto", "algorithm": "rsa-2048", "key_size": 2048}
    cbom_row = {
        "type": "cryptographic-asset", "name": "RSA 2048",
        "cryptoProperties": {"algorithmProperties": {
            "algorithm": "RSA-2048", "parameterSetIdentifier": "2048"}}}
    a = canonical_identity(techbom_row)
    b = canonical_identity(cbom_row)
    assert a["identity"] == b["identity"] == "crypto:RSA-2048"
    assert a["kind"] == b["kind"] == "crypto"


def test_vendor_and_application_identities():
    assert canonical_identity(
        {"type": "vendor", "name": "Thales"})["identity"] == "vendor:thales"
    assert canonical_identity(
        {"type": "application", "name": "Payment API"})["identity"] \
        == "application:payment api"


def test_unidentifiable_components_return_none():
    assert canonical_identity({"type": "crypto", "name": ""}) is None
    assert canonical_identity({}) is None


def test_index_keeps_provenance_not_merged_values():
    doc = {"components": [
        {"type": "crypto", "algorithm": "AES-128", "key_size": 128,
         "bom-ref": "crypto:12:host"},
    ]}
    rows = index_bom("cbom", doc)
    assert rows[0]["bom"] == "cbom"
    assert rows[0]["ref"] == "crypto:12:host"
    assert rows[0]["values"] == {"key size": "128"}


# ── pure: links + conflicts ──────────────────────────────────────────


def _three_boms():
    cbom = {"components": [
        {"type": "cryptographic-asset", "name": "RSA 2048", "bom-ref": "c1",
         "cryptoProperties": {"algorithmProperties": {
             "algorithm": "RSA-2048", "parameterSetIdentifier": "2048",
             "mode": "CBC"}}},
        {"type": "cryptographic-asset", "name": "AES 256", "bom-ref": "c2",
         "cryptoProperties": {"algorithmProperties": {
             "algorithm": "AES-256", "parameterSetIdentifier": "256"}}},
        {"type": "application", "name": "Payment API", "bom-ref": "c3"},
    ]}
    techbom = {"layers": {
        "cbom": {"components": [
            {"type": "crypto", "algorithm": "RSA-2048", "key_size": 1024,
             "bom-ref": "t1"},
        ]},
        "sbom": {"components": [
            {"type": "application", "name": "payment api", "bom-ref": "t2"},
        ]},
    }}
    vbom = {"components": [
        {"type": "vendor", "name": "Thales", "bom-ref": "v1",
         "risk_level": "HIGH"},
    ]}
    return {"cbom": cbom, "techbom": techbom, "vbom": vbom}


def test_links_across_boms_with_refs():
    result = cross_boms(_three_boms())
    identities = {link["identity"] for link in result["links"]}
    assert "crypto:RSA-2048" in identities
    assert "application:payment api" in identities
    # a vendor in one BOM only is NOT linked
    assert not any(l["identity"] == "vendor:thales" for l in result["links"])
    rsa_link = next(l for l in result["links"]
                    if l["identity"] == "crypto:RSA-2048")
    assert rsa_link["bom_count"] == 2
    refs = {entry["bom"]: entry["ref"] for entry in rsa_link["present_in"]}
    assert refs == {"cbom": "c1", "techbom": "t1"}


def test_key_size_disagreement_is_a_conflict():
    result = cross_boms(_three_boms())
    conflict = next(c for c in result["conflicts"]
                    if c["identity"] == "crypto:RSA-2048")
    # note: the identity carries cbom's 2048; techbom's row says 1024 —
    # the same algorithm, disagreeing key size
    assert conflict["field"] == "key size"
    values = {v["bom"]: v["value"] for v in conflict["values"]}
    assert values["cbom"] == "2048" and values["techbom"] == "1024"


def test_agreeing_boms_produce_no_conflicts():
    boms = {
        "cbom": {"components": [
            {"type": "cryptographic-asset", "name": "AES 256",
             "cryptoProperties": {"algorithmProperties": {
                 "algorithm": "AES-256", "parameterSetIdentifier": "256"}}}]},
        "techbom": {"layers": {"cbom": {"components": [
            {"type": "crypto", "algorithm": "AES-256", "key_size": 256}]}}},
    }
    result = cross_boms(boms)
    assert result["linked_identities"] == 1
    assert result["conflict_count"] == 0


def test_empty_and_malformed_documents_are_tolerated():
    result = cross_boms({"cbom": {}, "techbom": None})
    assert result["indexed"] == 0 and result["links"] == []
    assert cross_boms({})["model"] == "cross-bom/linking-v1"


# ── API end to end ───────────────────────────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/crossbom.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/crossbom.db"


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_cross_links_endpoint_over_live_inventory(sqlite_app):
    client, db_url = sqlite_app
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.crypto_asset import CryptoAsset

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    session.add(CryptoAsset(
        algorithm="RSA-2048", key_size=2048, purpose="ENCRYPTION",
        file_path="src/Keys.java", line_number=1, confidence="HIGH"))
    session.commit()
    session.close()
    eng.dispose()

    r = client.get("/api/v1/cbom/cross-links")
    assert r.status_code == 401  # authenticated surface

    admin = _login(client)
    r = client.get("/api/v1/cbom/cross-links", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "cross-bom/linking-v1"
    assert body["live"] is True
    assert set(body["boms"]) == {"cbom", "techbom", "vbom"}
    # the same crypto asset flows into both the generator CBOM and the
    # TechBOM cbom layer -> it must be linked
    assert any(link["identity"] == "crypto:RSA-2048"
               for link in body["links"])
    assert "single-generator merge remains open" in body["note"]
