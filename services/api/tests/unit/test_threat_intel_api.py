"""Crypto threat-intel advisories (deep/30, round 31): pure + end to end."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from vendor_intel.threat_intel import (
    AdvisoryError,
    advisory_relevance,
    build_advisory_bundle,
    validate_advisories,
    verify_advisory_bundle,
)

SECRET = "feed-signing-secret-0123456789"

ADVISORIES = [
    {
        "advisory_id": "NIST-IR-8547-DEPRECATE",
        "source": "NIST",
        "advisory_type": "DEPRECATION",
        "algorithm": "RSA-2048",
        "severity": "HIGH",
        "title": "RSA-2048 deprecated for new deployments",
        "summary": "Minimum 3072 bits for RSA signatures after 2030.",
        "url": "https://example.gov/ir-8547",
        "published_at": "2026-09-01T00:00:00+00:00",
        "effective_date": "2030-01-01T00:00:00+00:00",
        "details": {"minimum_bits": 3072},
    },
    {
        "advisory_id": "EAC-001",
        "source": "academic",
        "advisory_type": "ATTACK_UPDATE",
        "algorithm": "SHA-1",
        "severity": "CRITICAL",
        "title": "Chosen-prefix collision cost drops",
        "effective_date": "2026-01-01T00:00:00+00:00",
        "details": {"attack_cost_bits": 63.4},
    },
]


# ── pure ─────────────────────────────────────────────────────────────


def test_validate_advisories_and_duplicates():
    out = validate_advisories(ADVISORIES)
    assert out[0]["advisory_type"] == "DEPRECATION"
    assert out[0]["effective_date"].year == 2030
    with pytest.raises(AdvisoryError):
        validate_advisories([{"advisory_id": "x", "source": "s",
                              "advisory_type": "NOPE", "algorithm": "RSA"}])
    with pytest.raises(AdvisoryError):
        validate_advisories([ADVISORIES[0], ADVISORIES[0]])
    with pytest.raises(AdvisoryError):
        validate_advisories([{"advisory_id": "x", "source": "s",
                              "advisory_type": "DEPRECATION",
                              "severity": "ULTRA", "algorithm": "RSA"}])
    with pytest.raises(AdvisoryError):
        validate_advisories([{"advisory_id": "x", "source": "s",
                              "advisory_type": "DEPRECATION",
                              "algorithm": "RSA",
                              "published_at": "not-a-date"}])


def test_bundle_sign_verify_and_tamper():
    validated = validate_advisories(ADVISORIES)
    bundle = build_advisory_bundle(validated, secret=SECRET, bundle_id="feed-42")
    back = verify_advisory_bundle(bundle, secret=SECRET)
    assert len(back) == 2
    assert back[0]["advisory_id"] == "NIST-IR-8547-DEPRECATE"

    tampered = {**bundle, "package": {**bundle["package"],
                                      "advisories": [dict(a) for a in validated]}}
    tampered["package"]["advisories"][0]["severity"] = "CRITICAL"
    with pytest.raises(AdvisoryError, match="tampered"):
        verify_advisory_bundle(tampered, secret=SECRET)

    with pytest.raises(AdvisoryError, match="untrusted"):
        verify_advisory_bundle(bundle, secret="wrong-secret-entirely")

    # a bundle with an invalid entry yields NOTHING (no half-import)
    bad_entries = [dict(ADVISORIES[0]), {"advisory_id": "z", "advisory_type": "??"}]
    bad = build_advisory_bundle(bad_entries, secret=SECRET)
    with pytest.raises(AdvisoryError):
        verify_advisory_bundle(bad, secret=SECRET)


def test_relevance_timing_is_annotation_only():
    validated = validate_advisories(ADVISORIES)
    now = datetime(2026, 10, 11, tzinfo=timezone.utc)
    upcoming = advisory_relevance(validated[0], algorithm="RSA-2048", now=now)
    assert upcoming["timing"] == "UPCOMING"  # effective 2030
    assert "annotation only" in upcoming["note"]
    current = advisory_relevance(validated[1], algorithm="SHA-1", now=now)
    assert current["timing"] == "CURRENT"
    standing = advisory_relevance({**validated[1], "effective_date": None},
                                  algorithm="SHA-1", now=now)
    assert standing["timing"] == "STANDING"


# ── API end to end ───────────────────────────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):

    db_url = f"sqlite:///{tmp_path}/threat.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings

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


def test_advisory_import_query_annotate(sqlite_app):
    client, db_url = sqlite_app
    admin = _login(client)

    # direct admin import (validated)
    r = client.post("/api/v1/threat-intel/advisories/import",
                    headers=admin, json={"advisories": ADVISORIES})
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 2

    # idempotent re-import → updated, not duplicated
    r = client.post("/api/v1/threat-intel/advisories/import",
                    headers=admin, json={"advisories": ADVISORIES})
    assert r.status_code == 200
    assert r.json()["created"] == 0 and r.json()["updated"] == 2

    # invalid entries rejected whole
    r = client.post("/api/v1/threat-intel/advisories/import",
                    headers=admin,
                    json={"advisories": [{"advisory_id": "bad", "advisory_type": "?"}]})
    assert r.status_code == 422

    # query by algorithm
    r = client.get("/api/v1/threat-intel/advisories", params={"algorithm": "SHA-1"})
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["advisories"][0]["advisory_id"] == "EAC-001"

    r = client.get("/api/v1/threat-intel/algorithms/RSA-2048")
    assert [a["advisory_id"] for a in r.json()["annotations"]] == \
        ["NIST-IR-8547-DEPRECATE"]
    assert r.json()["annotations"][0]["timing"] == "UPCOMING"

    # asset annotation: seed a crypto asset with RSA-2048
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.crypto_asset import CryptoAsset

    eng = create_engine(db_url)
    Session = sessionmaker(bind=eng)
    session = Session()
    asset = CryptoAsset(algorithm="RSA-2048", purpose="ENCRYPTION",
                        file_path="src/pay/Pay.java", key_size=2048, confidence="HIGH")
    session.add(asset)
    session.commit()
    asset_id = asset.id
    session.close()
    eng.dispose()

    r = client.get(f"/api/v1/threat-intel/assets/{asset_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["algorithm"] == "RSA-2048"
    assert body["advisory_count"] == 1
    assert body["annotations"][0]["severity"] == "HIGH"
    assert "annotation only" in body["note"]

    r = client.get("/api/v1/threat-intel/assets/nope")
    assert r.status_code == 404


def test_signed_bundle_import(sqlite_app):
    client, _db_url = sqlite_app
    admin = _login(client)

    bundle = build_advisory_bundle(validate_advisories(ADVISORIES),
                                   secret=SECRET, bundle_id="offline-feed-1")
    r = client.post("/api/v1/threat-intel/advisories/import",
                    headers=admin, json={"bundle": bundle, "secret": SECRET})
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 2

    # tampered bundle rejected with nothing persisted
    bundle["package"]["advisories"][0]["severity"] = "CRITICAL"
    r = client.post("/api/v1/threat-intel/advisories/import",
                    headers=admin, json={"bundle": bundle, "secret": SECRET})
    assert r.status_code == 422
    assert "tampered" in r.json()["detail"]

    # count unchanged after the rejected import
    r = client.get("/api/v1/threat-intel/advisories")
    assert r.json()["count"] == 2

    # bundle without secret → 422
    r = client.post("/api/v1/threat-intel/advisories/import",
                    headers=admin, json={"bundle": bundle})
    assert r.status_code == 422

    # issuer endpoint builds a verifiable bundle
    r = client.post("/api/v1/threat-intel/advisories/bundle",
                    headers=admin, json={"advisories": ADVISORIES, "secret": SECRET})
    assert r.status_code == 200
    rebuilt = verify_advisory_bundle(r.json(), secret=SECRET)
    assert len(rebuilt) == 2
