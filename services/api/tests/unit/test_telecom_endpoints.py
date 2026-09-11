"""Telecom API endpoints — registry CRUD, bounded scans, operator ingest.

Same fixture pattern as the banking endpoint tests: in-memory SQLite via
app_db, real minted sessions for the RBAC dependency, isolated registry and
snapshot paths per test (CRYPTOSCAN_TELECOM_REGISTRY / CRYPTOSCAN_SNAPSHOT_DIR).
The probe layer is monkeypatched — endpoint tests must not depend on the network.
"""

from __future__ import annotations

import db.models  # noqa: F401 — register all tables
import pytest
from api.dependencies import get_db_session
from api.main import create_app
from db.connection.session import Base, configure_session
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool


@pytest.fixture(autouse=True)
def _reset_telecom_snapshot_store():
    """The router caches the last snapshot in a module global; isolate tests."""
    from api.routers import telecom as telecom_router

    def _reset():
        with telecom_router._LOCK:
            telecom_router._SNAPSHOT = None

    _reset()
    yield
    _reset()


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_TELECOM_REGISTRY", str(tmp_path / "telecom_registry.json"))
    monkeypatch.setenv("CRYPTOSCAN_SNAPSHOT_DIR", str(tmp_path))

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure_session(engine)
    from sqlalchemy.orm import sessionmaker

    session = sessionmaker(bind=engine, expire_on_commit=False)()

    application = create_app()

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    application.state.test_session = session
    yield application
    application.dependency_overrides.clear()


def _mint(session, username: str, roles: list[str]) -> str:
    from datetime import datetime, timedelta, timezone

    from api.security.passwords import hash_password
    from api.security.session_manager import SessionManager
    from db.repositories.user_repository import UserRepository

    repo = UserRepository(session)
    if repo.get_by_username(username) is None:
        repo.create_user(username, hash_password("x"), roles)
        session.commit()
    token = SessionManager().create_session(username, roles=roles)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    repo.create_session(token, username, expires, ip="127.0.0.1")
    session.commit()
    return token


def _auth(session, roles: list[str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {_mint(session, 'tel-' + roles[0], roles)}"}


async def _add_carrier(client, headers):
    return await client.post("/api/v1/telecom/carriers", headers=headers, json={
        "code": "de-telekom", "name": "Deutsche Telekom", "country": "de",
        "plmn": "262-01", "legal_entity": "dt-group",
    })


@pytest.mark.asyncio
async def test_carrier_and_target_registry_crud(app_db):
    session = app_db.state.test_session
    headers = _auth(session, ["security_analyst"])  # telecom.manage
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        added = await _add_carrier(client, headers)
        assert added.status_code == 200, added.text
        assert added.json()["carrier"]["plmn"] == "262-01"

        bad = await client.post("/api/v1/telecom/carriers", headers=headers, json={
            "code": "fr-orange", "name": "Orange", "country": "fr", "plmn": "26-1"})
        assert bad.status_code == 422

        target = await client.post("/api/v1/telecom/targets", headers=headers, json={
            "nf_id": "amf-prod-01", "nf_type": "amf",
            "endpoint": "sba.example:443", "carrier_code": "de-telekom"})
        assert target.status_code == 200, target.text

        orphan = await client.post("/api/v1/telecom/targets", headers=headers, json={
            "nf_id": "gw-1", "nf_type": "ipsecgw", "endpoint": "za.example:500",
            "carrier_code": "nope"})
        assert orphan.status_code == 422

        dup = await client.post("/api/v1/telecom/targets", headers=headers, json={
            "nf_id": "bad-type", "nf_type": "webserver", "endpoint": "h.example:443"})
        assert dup.status_code == 422

        reg = await client.get("/api/v1/telecom/registry", headers=_auth(session, ["readonly"]))
        assert reg.status_code == 200
        body = reg.json()
        assert body["counts"] == {"carriers": 1, "targets": 1}
        assert "amf" in body["nf_catalog"]

        deleted = await client.delete("/api/v1/telecom/carriers/de-telekom", headers=headers)
        assert deleted.status_code == 200
        missing = await client.delete("/api/v1/telecom/carriers/de-telekom", headers=headers)
        assert missing.status_code == 404


@pytest.mark.asyncio
async def test_scan_probes_registered_targets_and_publishes_events(app_db, monkeypatch):
    from telecom_scanner.classify import classify_target
    from telecom_scanner.registry import normalize_target

    session = app_db.state.test_session
    headers = _auth(session, ["security_analyst"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        await _add_carrier(client, headers)
        added = await client.post("/api/v1/telecom/targets", headers=headers, json={
            "nf_id": "amf-prod-01", "nf_type": "amf", "endpoint": "sba.example:443",
            "carrier_code": "de-telekom"})
        assert added.status_code == 200

        target = normalize_target({"nf_id": "amf-prod-01", "nf_type": "amf",
                                   "endpoint": "sba.example:443", "carrier_code": "de-telekom"})

        def make_probe(expiry_status, days, not_after):
            return {"status": "OK", "crypto": {"tls_version": "TLSv1.3",
                                               "cipher_suite": "TLS_AES_256_GCM_SHA384"},
                    "certificates": [{"expiry_status": expiry_status, "days_until_expiry": days,
                                      "is_self_signed": False, "not_after": not_after}],
                    "chain_validation": {"is_valid": True, "errors": []}}

        probes = [
            make_probe("VALID", 200, "2027-03-01T00:00:00+00:00"),     # pass 1: healthy
            make_probe("EXPIRING_SOON", 21, "2026-10-01T00:00:00+00:00"),  # pass 2: expiring
        ]

        def fake_probe_registry(registry, *, only=None, timeout=4.0, max_workers=8):
            return [classify_target(target, probes.pop(0))] if probes else []

        monkeypatch.setattr("telecom_scanner.main.probe_registry", fake_probe_registry)

        first = await client.post("/api/v1/telecom/scan", headers=_auth(session, ["ciso"]),
                                  json={"timeout": 1.0})
        assert first.status_code == 200, first.text
        first_body = first.json()
        assert first_body["scanned"] == 1
        assert first_body["rollup"]["totals"]["targets"] == 1
        # first pass is the baseline: no per-target noise for a healthy NF
        assert first_body["events"] == []

        second = await client.post("/api/v1/telecom/scan", headers=_auth(session, ["ciso"]),
                                   json={"timeout": 1.0})
        assert second.status_code == 200, second.text
        body = second.json()
        assert body["rollup"]["totals"]["expiring_certs"] == 1
        kinds = [e["kind"] for e in body["events"]]
        assert "TELECOM_CERT_EXPIRING" in kinds

        events = await client.get("/api/v1/telecom/events", headers=_auth(session, ["readonly"]))
        assert events.status_code == 200
        published = [e for e in events.json()["events"] if e["type"] == "telecom.event"]
        assert published, "scan events must reach the platform bus"

        unknown = await client.post("/api/v1/telecom/scan", headers=headers,
                                    json={"only": ["does-not-exist"]})
        assert unknown.status_code == 422


@pytest.mark.asyncio
async def test_ingest_classifies_operator_side_ike(app_db):
    session = app_db.state.test_session
    manage = _auth(session, ["security_analyst"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        await _add_carrier(client, manage)
        await client.post("/api/v1/telecom/targets", headers=manage, json={
            "nf_id": "gw-za-01", "nf_type": "ipsecgw", "endpoint": "za.example:500",
            "carrier_code": "de-telekom"})

        ingest = await client.post("/api/v1/telecom/ingest",
                                   headers=_auth(session, ["scanner"]),
                                   json={"target_id": "gw-za-01",
                                         "probe": {"ike": {"ike_version": "IKEv1",
                                                           "dh_groups": ["2"],
                                                           "encryption": "3DES"}}})
        assert ingest.status_code == 200, ingest.text
        verdict = ingest.json()["verdict"]
        assert verdict["status"] == "IPSEC_REVIEWED"
        assert verdict["severity"] == "critical"

        missing = await client.post("/api/v1/telecom/ingest",
                                    headers=_auth(session, ["scanner"]),
                                    json={"target_id": "ghost", "probe": {}})
        assert missing.status_code == 404


@pytest.mark.asyncio
async def test_posture_is_honest_before_any_scan(app_db):
    session = app_db.state.test_session
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        posture = await client.get("/api/v1/telecom/posture", headers=_auth(session, ["readonly"]))
        assert posture.status_code == 200
        body = posture.json()
        assert body["has_data"] is False
        assert "No telecom scan" in body["message"]
        assert body["rollup"] is None


@pytest.mark.asyncio
async def test_rbac_matrix(app_db):
    session = app_db.state.test_session
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        readonly = _auth(session, ["readonly"])
        denied = await client.post("/api/v1/telecom/carriers", headers=readonly, json={
            "code": "x-carrier", "name": "Nope Carrier", "country": "de", "plmn": "262-02"})
        assert denied.status_code == 403
        assert "telecom.manage" in denied.json()["detail"]

        scanner = _auth(session, ["scanner"])
        denied_ingest_admin = await client.delete("/api/v1/telecom/targets/whatever", headers=scanner)
        assert denied_ingest_admin.status_code == 403

        anonymous = await client.get("/api/v1/telecom/posture")
        assert anonymous.status_code == 401
