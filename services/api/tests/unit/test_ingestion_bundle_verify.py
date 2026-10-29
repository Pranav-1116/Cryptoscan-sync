"""The ingestion gate over HTTP (spec 100).

The module test suite already pins the format. These tests pin the part that turns a
verdict into a deployment answer: the route must not accept a bundle on trust, must not
report a transport success as an ingest, and must state when this deployment has no
collector key configured at all.
"""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.models.base import Base
from shared_models import evidence_bundle, release_signature


@pytest.fixture
def api():
    """The real app with SQLite and a signed-in tester; the route needs nothing else."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "tester"
    app.dependency_overrides[get_db_session] = lambda: session
    try:
        yield TestClient(app), session
    finally:
        session.close()
        app.dependency_overrides.clear()


@pytest.fixture
def keys(tmp_path: Path):
    return release_signature.generate_keypair(tmp_path / "keys", name="collector")


def _bundle(keys, *, signed: bool = True) -> dict:
    members = {
        "observations/linux/host-01.json": b'{"host":"host-01","packages":["openssl"]}',
        "observations/network/tls-01.json": b'{"endpoint":"10.0.0.5:443","tls":"1.3"}',
    }
    manifest = evidence_bundle.build_manifest(
        bundle_id="BND-2026-00182",
        organization_id="BANK-001",
        environment="production",
        scan_id="SCAN-2026-00182",
        collector_version="1.0.0",
        scope_revision="REV-192",
        created_at="2026-10-29T08:30:00Z",
        members=members,
        coverage={"expected": 2, "collected": 2},
    )
    if signed:
        manifest["signature"] = release_signature.sign_document(
            manifest, release_signature.load_private_key(keys["private_key"])
        )
    return {
        "manifest": manifest,
        "members": {path: base64.b64encode(data).decode("ascii") for path, data in members.items()},
    }


def _trust(monkeypatch, keys) -> None:
    import api.routers.ingestion as ingestion

    trusted = release_signature.load_public_key(keys["public_key"])
    monkeypatch.setattr(ingestion, "trusted_keys", lambda: [trusted])


def test_a_key_verified_bundle_is_accepted_and_projection_is_not_claimed(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)

    response = http.post("/api/v1/ingestion/bundles/verify", json=_bundle(keys))

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == evidence_bundle.VERIFIED
    assert body["accepted"] is True
    assert body["members_checked"] == 2
    assert body["trusted_keys_configured"] == 1
    # verification is the gate; the six projections are explicitly not claimed here
    assert body["projection"]["state"] == "NOT_ATTEMPTED"
    assert "does not yet normalise" in body["projection"]["reason"]
    assert body["coverage"]["state"] == "COMPLETE"


def test_without_a_configured_key_the_deployment_says_so_and_refuses(api, keys, monkeypatch):
    http, _session = api
    import api.routers.ingestion as ingestion

    monkeypatch.setattr(ingestion, "trusted_keys", lambda: [])

    body = http.post("/api/v1/ingestion/bundles/verify", json=_bundle(keys)).json()

    assert body["state"] == evidence_bundle.SIGNATURE_UNCHECKED
    assert body["accepted"] is False
    assert body["trusted_keys_configured"] == 0
    assert any("NO_TRUSTED_COLLECTOR_KEY" in finding for finding in body["deployment_findings"])


def test_an_unsigned_bundle_is_not_accepted_even_with_a_trust_root(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)

    body = http.post("/api/v1/ingestion/bundles/verify", json=_bundle(keys, signed=False)).json()

    assert body["state"] == evidence_bundle.UNSIGNED
    assert body["accepted"] is False
    assert body["received"]["members"] == 2


def test_a_tampered_member_is_rejected_by_name(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)
    payload = _bundle(keys)
    payload["members"]["observations/network/tls-01.json"] = base64.b64encode(b'{"tls":"1.0"}').decode()

    body = http.post("/api/v1/ingestion/bundles/verify", json=payload).json()

    assert body["state"] == evidence_bundle.REJECTED
    assert body["accepted"] is False
    assert body["members_mismatched"] == ["observations/network/tls-01.json"]


def test_a_member_that_is_not_base64_is_a_verdict_not_a_500(api, keys, monkeypatch):
    http, _session = api
    _trust(monkeypatch, keys)
    payload = _bundle(keys)
    payload["members"]["observations/linux/host-01.json"] = "not base64!!"

    response = http.post("/api/v1/ingestion/bundles/verify", json=payload)

    assert response.status_code == 422
    assert "MEMBER_NOT_BASE64" in response.text


def test_the_schema_route_states_the_format_and_its_limits(api):
    http, _session = api

    body = http.get("/api/v1/ingestion/bundles/schema").json()

    assert body["schema"] == evidence_bundle.BUNDLE_SCHEMA
    assert body["signature_schema"] == release_signature.SCHEMA
    assert "observations" in body["member_kinds"]
    assert evidence_bundle.VERIFIED in body["states"]
    assert evidence_bundle.MEMBER_DIGEST_MISMATCH in body["reason_codes"]
    assert body["trust"]["configured"] in (True, False)
    assert body["projection"] == "NOT_ATTEMPTED"
    assert any("chunked" in limit for limit in body["limits"])
