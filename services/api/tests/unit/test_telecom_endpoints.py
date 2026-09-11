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
from db.models import CryptoAsset, System, SystemAsset
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


def _lei(body: str = "BANKDE123456") -> str:
    """Valid ISO 17442 LEI for the given 18-char body (ISO 7064 MOD 97-10)."""
    cs = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b = body.upper().ljust(18, "X")[:18]
    n = int("".join(str(cs.index(c)) for c in b) + "00")
    return b + f"{98 - (n % 97):02d}"


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
        assert body["counts"] == {"carriers": 1, "targets": 1, "roaming_partners": 0}
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


# ------------------------------------------------------- roadmap + roaming

def _seed_snapshot(rows):
    from api.routers import telecom as telecom_router

    with telecom_router._LOCK:
        telecom_router._SNAPSHOT = {"generated_at": "2026-09-11T04:00:00+00:00",
                                    "rows": rows, "state": {}, "events": []}


@pytest.mark.asyncio
async def test_roadmap_endpoint_buckets_carrier_families(app_db):
    session = app_db.state.test_session
    manage = _auth(session, ["security_analyst"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        await _add_carrier(client, manage)
        from telecom_scanner.classify import classify_target
        from telecom_scanner.registry import normalize_target

        target = normalize_target({"nf_id": "amf-prod-01", "nf_type": "amf",
                                   "endpoint": "sba.example:443", "carrier_code": "de-telekom"})
        probe = {"status": "OK", "crypto": {"tls_version": "TLSv1.2",
                                            "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
                 "certificates": [{"expiry_status": "VALID", "days_until_expiry": 100,
                                   "is_self_signed": False, "key_size": 2048, "key_type": "rsa",
                                   "signature_algorithm": "sha1WithRSAEncryption"}],
                 "chain_validation": {"is_valid": True, "errors": []}}
        _seed_snapshot([classify_target(target, probe)])

        roadmap = await client.get("/api/v1/telecom/roadmap", headers=_auth(session, ["readonly"]))
        assert roadmap.status_code == 200
        body = roadmap.json()
        buckets = {row["family"]: row["bucket"] for row in body["rows"]}
        assert buckets == {"3DES-112": "immediate", "SHA1WITHRSA-2048": "immediate",
                           "RSA-2048": "by-2030"}
        assert body["summary"]["entities_affected"] == ["de-telekom"]


@pytest.mark.asyncio
async def test_roaming_partner_crud_and_matrix(app_db):
    session = app_db.state.test_session
    manage = _auth(session, ["security_analyst"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        await _add_carrier(client, manage)
        await client.post("/api/v1/telecom/targets", headers=manage, json={
            "nf_id": "sepp-01", "nf_type": "sepp", "endpoint": "roam.example:443",
            "carrier_code": "de-telekom"})

        added = await client.post("/api/v1/telecom/roaming-partners", headers=manage, json={
            "carrier_code": "de-telekom", "partner_plmn": "208-01",
            "partner_name": "Orange France", "country": "fr"})
        assert added.status_code == 200, added.text
        assert added.json()["partner"]["id"] == "de-telekom:208-01"

        orphan = await client.post("/api/v1/telecom/roaming-partners", headers=manage, json={
            "carrier_code": "ghost", "partner_plmn": "208-01",
            "partner_name": "No Carrier", "country": "fr"})
        assert orphan.status_code == 422

        _seed_snapshot([])
        matrix = await client.get("/api/v1/telecom/roaming", headers=_auth(session, ["readonly"]))
        assert matrix.status_code == 200
        body = matrix.json()
        assert body["summary"]["partners"] == 1
        assert body["rows"][0]["status"] == "unknown"  # no scan has run

        denied = await client.post("/api/v1/telecom/roaming-partners", headers=_auth(session, ["readonly"]),
                                   json={"carrier_code": "de-telekom", "partner_plmn": "262-02",
                                         "partner_name": "Vodafone", "country": "de"})
        assert denied.status_code == 403

        deleted = await client.delete("/api/v1/telecom/roaming-partners/de-telekom:208-01", headers=manage)
        assert deleted.status_code == 200
        gone = await client.delete("/api/v1/telecom/roaming-partners/de-telekom:208-01", headers=manage)
        assert gone.status_code == 404


@pytest.mark.asyncio
async def test_banking_roadmap_folds_telecom_families(app_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_GROUP_ENTITIES", str(tmp_path / "reg.json"))
    from telecom_scanner.classify import classify_target
    from telecom_scanner.registry import normalize_target

    # telecom side: a carrier tied to the bank's legal entity
    target = normalize_target({"nf_id": "amf-prod-01", "nf_type": "amf",
                               "endpoint": "sba.example:443", "carrier_code": "de-telekom"})
    probe = {"status": "OK", "crypto": {"tls_version": "TLSv1.3",
                                        "cipher_suite": "TLS_AES_256_GCM_SHA384"},
             "certificates": [{"expiry_status": "VALID", "days_until_expiry": 100,
                               "is_self_signed": False, "key_size": 2048, "key_type": "rsa",
                               "signature_algorithm": "sha256WithRSAEncryption"}],
             "chain_validation": {"is_valid": True, "errors": []}}

    session = app_db.state.test_session
    manage = _auth(session, ["security_analyst"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        await client.post("/api/v1/telecom/carriers", headers=manage, json={
            "code": "de-telekom", "name": "Deutsche Telekom", "country": "de",
            "plmn": "262-01", "legal_entity": "bank-de"})
        _seed_snapshot([classify_target(target, probe)])

        # banking side: register the entity + one system with RSA-2048
        sup = _auth(app_db.state.test_session, ["supervisor"])
        created = await client.post("/api/v1/banking/group/entities", headers=sup,
                                    json={"code": "bank-de", "name": "Bank DE",
                                          "jurisdiction": "de", "lei": _lei()})
        assert created.status_code in (200, 201), created.text
        s = app_db.state.test_session
        s.add(CryptoAsset(id="ca-rsa", algorithm="RSA", file_path="src/Pay.java",
                          purpose="key_exchange", key_size=2048, confidence=1.0))
        s.add(System(id="sys-bank", name="core-banking"))
        s.add(SystemAsset(system_id="sys-bank", asset_id="ca-rsa"))
        s.commit()
        assigned = await client.put("/api/v1/banking/group/systems/sys-bank/entity",
                                    headers=sup, json={"entity_code": "bank-de"})
        assert assigned.status_code == 200

        merged = await client.get("/api/v1/banking/group/roadmap?include_telecom=true", headers=sup)
        assert merged.status_code == 200
        body = merged.json()
        assert body["telecom"]["carriers_folded"] == 1
        by_family = {}
        for row in body["rows"]:
            if row["entity_code"] == "bank-de":
                by_family[row["family"]] = row["bucket"]
        # bank asset + telecom NF land in ONE plan for the SAME entity
        assert by_family.get("RSA-2048") == "by-2030"
        assert body["summary"]["instances_by_bucket"]["by-2030"] >= 2

        plain = await client.get("/api/v1/banking/group/roadmap", headers=sup)
        assert "telecom" not in plain.json()


@pytest.mark.asyncio
async def test_carrier_pack_endpoint_scopes_and_csv(app_db):
    session = app_db.state.test_session
    manage = _auth(session, ["security_analyst"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        await _add_carrier(client, manage)
        await client.post("/api/v1/telecom/targets", headers=manage, json={
            "nf_id": "amf-prod-01", "nf_type": "amf", "endpoint": "sba.example:443",
            "carrier_code": "de-telekom"})
        await client.post("/api/v1/telecom/targets", headers=manage, json={
            "nf_id": "amf-fr-01", "nf_type": "amf", "endpoint": "sba-fr.example:443",
            "carrier_code": "fr-orange"})
        await client.post("/api/v1/telecom/carriers", headers=manage, json={
            "code": "fr-orange", "name": "Orange", "country": "fr", "plmn": "208-01"})
        from telecom_scanner.classify import classify_target
        from telecom_scanner.registry import normalize_target

        t1 = normalize_target({"nf_id": "amf-prod-01", "nf_type": "amf",
                               "endpoint": "sba.example:443", "carrier_code": "de-telekom"})
        t2 = normalize_target({"nf_id": "amf-fr-01", "nf_type": "amf",
                               "endpoint": "sba-fr.example:443", "carrier_code": "fr-orange"})
        _seed_snapshot([
            classify_target(t1, {"status": "TIMEOUT"}),
            classify_target(t2, {"status": "OK", "crypto": {"tls_version": "TLSv1.2",
                                                            "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
                                 "certificates": [{"expiry_status": "VALID", "days_until_expiry": 100,
                                                   "is_self_signed": False, "key_size": 2048,
                                                   "key_type": "rsa",
                                                   "signature_algorithm": "sha1WithRSAEncryption"}],
                                 "chain_validation": {"is_valid": True, "errors": []}}),
        ])

        pack = await client.get("/api/v1/telecom/pack?carrier=de-telekom",
                                headers=_auth(session, ["readonly"]))
        assert pack.status_code == 200
        body = pack.json()
        assert body["pack"]["carrier_code"] == "de-telekom"
        assert body["posture"]["totals"]["targets"] == 1        # scoped, not the whole estate
        assert body["posture"]["totals"]["unreachable"] == 1
        assert len(body["declared_limits"]) == 3

        csv_resp = await client.get("/api/v1/telecom/pack?carrier=de-telekom&format=csv",
                                    headers=_auth(session, ["readonly"]))
        assert csv_resp.status_code == 200
        assert csv_resp.headers["content-type"].startswith("text/csv")
        assert "telecom-pack-de-telekom" in csv_resp.headers["content-disposition"]

        unknown = await client.get("/api/v1/telecom/pack?carrier=ghost",
                                   headers=_auth(session, ["readonly"]))
        assert unknown.status_code == 404


@pytest.mark.asyncio
async def test_telecom_events_drive_the_automation_bridge(app_db, monkeypatch):
    """The bridge maps telecom events onto the SAME rules engine — proven
    end-to-end with a real rule: a REACHABILITY_LOST event (agent_offline)
    triggers the seeded rule and produces an automation plan with actions."""
    from api.events import automation_bridge
    from api.routers.automation import run_automation

    session = app_db.state.test_session
    calls = []
    real_run = run_automation

    def spy_run(db, **kwargs):
        result = real_run(db, **kwargs)
        calls.append((kwargs.get("event_kind"), result))
        return result

    monkeypatch.setattr("api.routers.automation.run_automation", spy_run)

    # a rule that fires on agent_offline
    from automation.rules_engine import AutomationRule
    from api.routers.automation import _load_rules
    import api.routers.automation as auto_router

    rule = AutomationRule(id="tel-down", name="NF down", when="agent_offline",
                          conditions=[], actions=["create_alert"], severity="HIGH")
    monkeypatch.setattr(auto_router, "_load_rules", lambda db: [rule])

    automation_bridge._handle({
        "id": 1, "ts": "2026-09-11T04:00:00+00:00", "type": "telecom.event",
        "source": "telecom-scanner",
        "payload": {"kind": "TELECOM_REACHABILITY_LOST", "severity": "critical",
                    "target": "amf-1", "nf_id": "amf-1", "nf_type": "amf",
                    "carrier_code": "de-telekom", "plane": "5gc",
                    "message": "amf-1 became unreachable"},
    })
    assert calls and calls[0][0] == "agent_offline"
    plan = calls[0][1]
    assert plan, "rule must produce an automation plan"

    # noise must NOT reach the engine
    calls.clear()
    automation_bridge._handle({
        "id": 2, "ts": "2026-09-11T04:01:00+00:00", "type": "telecom.event",
        "source": "telecom-scanner",
        "payload": {"kind": "TELECOM_RECOVERED", "severity": "info"},
    })
    assert calls == []
