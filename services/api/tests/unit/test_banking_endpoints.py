"""Banking & Regulatory API endpoints.

Same fixture pattern as the technology-BOM endpoint tests: in-memory SQLite via
the app_db fixture, ASGITransport + AsyncClient, real materialization path.
"""

from __future__ import annotations

import db.models  # noqa: F401 — register all tables
import pytest
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models import CryptoAsset, HardwareAsset, System, SystemAsset
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def app_db():
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    application.state.test_session = session

    session.add_all([
        CryptoAsset(id="ca-rsa", algorithm="RSA", file_path="src/Pay.java",
                    purpose="key_exchange", key_size=2048, confidence=1.0),
        CryptoAsset(id="ca-aes", algorithm="AES", file_path="src/Store.java",
                    purpose="encryption", key_size=256, confidence=1.0),
        HardwareAsset(id="hw-hsm-1", asset_id="HSM-0001", manufacturer="Thales",
                      model="Luna Network HSM", device_type="hsm",
                      firmware={"version": "7.8.9"},
                      hsm={"algorithms": ["ML-KEM"]}),
    ])
    session.commit()

    yield application

    application.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_banking_overview_returns_regulatory_surface(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        resp = await client.get("/api/v1/banking/overview")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "technology_bom"
    ov = body["overview"]
    assert ov["hndl"]["at_risk"] is True          # RSA-2048 key exchange
    assert ov["hsm"]["total"] == 1
    assert ov["hsm"]["pqc_ready"] == 1            # declares ML-KEM
    assert ov["roadmap"]["total_in_scope"] >= 1


@pytest.mark.asyncio
async def test_banking_action_plan_frameworks(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        ecb = await client.get("/api/v1/banking/action-plan?framework=ecb&institution=Test%20Bank")
        generic = await client.get("/api/v1/banking/action-plan")
        bad = await client.get("/api/v1/banking/action-plan?framework=madeup")
    assert ecb.status_code == 200 and generic.status_code == 200
    assert bad.status_code == 422
    ecb_body = ecb.json()
    assert ecb_body["framework"] == "ecb"
    assert ecb_body["institution"] == "Test Bank"
    assert any("ECB" in ref for ref in ecb_body["references"])
    assert ecb_body["evidence"]["snapshot_id"]
    assert ecb_body["assessment"]["admission"]["decision"] in ("PASS", "WARN", "FAIL")
    assert isinstance(ecb_body["phases"], list) and len(ecb_body["phases"]) == 4
    assert isinstance(ecb_body["hndl_register"], list)


@pytest.mark.asyncio
async def test_banking_hndl_and_roadmap_endpoints(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        hndl = await client.get("/api/v1/banking/hndl")
        roadmap = await client.get("/api/v1/banking/roadmap")
    assert hndl.status_code == 200
    assert hndl.json()["total"] == 1  # RSA-2048 key exchange only
    entry = hndl.json()["entries"][0]
    assert entry["deadline"] == 2030 and entry["exposure"] == "critical"
    assert roadmap.status_code == 200
    phases = {p["phase"] for p in roadmap.json()["phases"]}
    assert phases == {"P1", "P2", "P3", "P4"}


@pytest.mark.asyncio
async def test_banking_hsm_fleet_endpoint(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        resp = await client.get("/api/v1/banking/hsm")
    assert resp.status_code == 200
    fleet = resp.json()["fleet"]
    assert fleet["total"] == 1 and fleet["pqc_ready"] == 1
    assert fleet["hsms"][0]["fips"]["status"] == "validated"  # Thales Luna family


RACDCERT = """Digital certificate information for site certificate PAYGW:
    Status: TRUST
    Expiration Date: 2027/01/01 00:00:00
    Certificate Key Size: 2048
    Algorithm Signature: SHA256WithRSA
    Subject: CN=paygw.bank
"""


@pytest.mark.asyncio
async def test_mainframe_ingest_persists_into_unified_inventory(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        first = await client.post("/api/v1/banking/mainframe/ingest", json={
            "kind": "racdcert", "content": RACDCERT})
        again = await client.post("/api/v1/banking/mainframe/ingest", json={
            "kind": "racdcert", "content": RACDCERT})
        inv = await client.get("/api/v1/banking/mainframe")
        bad = await client.post("/api/v1/banking/mainframe/ingest", json={
            "kind": "nonsense", "content": "x"})
    assert first.status_code == 200 and again.status_code == 200
    assert first.json()["inserted"] == 1
    assert again.json()["duplicates"] == 1 and again.json()["inserted"] == 0  # idempotent
    assert bad.status_code == 422
    body = inv.json()
    assert body["total"] == 1 and body["by_source"] == {"zos-racf": 1}
    asset = body["assets"][0]
    assert asset["algorithm"] == "RSA" and asset["key_size"] == 2048
    assert asset["quantum"]["transition"] in ("deprecated_after_2030", "disallowed_after_2035")

    # the ingest must be visible in the UNIFIED BOM (same crypto_assets table)
    session = app_db.state.test_session
    rows = list(session.query(CryptoAsset).filter(
        CryptoAsset.source_language == "zos-racf").all())
    assert len(rows) == 1 and rows[0].file_path == "racf://PAYGW"


# --------------------------------------------------------------------------- #
# Deep mainframe / HSM / exports / integrations / FIPS registry
# --------------------------------------------------------------------------- #

DB2_EXTRACT = ("[database PAYDB]\nSSL_VERSIONS = TLSv1,TLSv1.2\n"
               "SSL_CIPHERSPECS = TLS_RSA_WITH_DES_CBC_SHA\nSSL_SVC_LABEL = PAYCERT\n"
               "[database HRDB]\nDB2Z = x\n")

CICS_EXTRACT = ("TCPIPSERVICE(PAYMENTS) PORTNUMBER(9443) PROTOCOL(https) CERTIFICATE(PAYGW)\n"
                "TCPIPSERVICE(LEGACY) PORTNUMBER(2000) PROTOCOL(http)\n")


@pytest.mark.asyncio
async def test_mainframe_analyze_db2_and_cics(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        db2 = await client.post("/api/v1/banking/mainframe/analyze",
                                json={"kind": "db2_tls", "content": DB2_EXTRACT, "persist": False})
        cics = await client.post("/api/v1/banking/mainframe/analyze",
                                 json={"kind": "cics_tcpservice", "content": CICS_EXTRACT, "persist": False})
        bad = await client.post("/api/v1/banking/mainframe/analyze",
                                json={"kind": "wat", "content": "x"})
    assert db2.status_code == 200 and cics.status_code == 200 and bad.status_code == 422
    a = db2.json()["assessment"]
    assert a["cleartext_endpoints"], "HRDB without SSL must surface"
    assert a["weak_transport"][0]["weak_ciphers"] == ["TLS_RSA_WITH_DES_CBC_SHA"]
    c = cics.json()["assessment"]
    assert len(c["cleartext_endpoints"]) == 1


@pytest.mark.asyncio
async def test_action_plan_export_formats_and_owners(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        html = await client.get("/api/v1/banking/action-plan/export?format=html&framework=ecb")
        csv_resp = await client.get("/api/v1/banking/action-plan/export?format=csv&framework=fca")
        blob = await client.get("/api/v1/banking/action-plan/export?format=json")
        bad = await client.get("/api/v1/banking/action-plan/export?format=docx")
    assert html.status_code == 200 and csv_resp.status_code == 200 and blob.status_code == 200
    assert bad.status_code == 422
    assert "attachment" in html.headers["content-disposition"]
    assert html.text.lstrip().startswith("<!doctype html")
    assert csv_resp.text.splitlines()[0].startswith("algorithm,key_size")
    assert blob.json()["document"] == "cryptographic-risk-action-plan"


@pytest.mark.asyncio
async def test_hsm_parse_and_deep(app_db):
    slots = ("Slot 0 (0x80000000): Luna\n  token label: pay-p1\n  token model: Luna K7\n"
             "  firmware version: 7.8.4\n")
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        parsed = await client.post("/api/v1/banking/hsm/parse", json={
            "slots_text": slots, "objects_text": "Slot 0:\n  Private Key Object\n    label: k1\n",
            "manufacturer": "Thales", "model": "Luna Network HSM"})
        deep = await client.get("/api/v1/banking/hsm/deep")
    assert parsed.status_code == 200
    one = parsed.json()["assessment"]["hsms"][0]
    assert one["pqc_status"] in ("ready", "not_declared", "unknown")
    assert one["key_objects"] == 1
    assert deep.status_code == 200
    assert deep.json()["fleet"]["total"] == 1


@pytest.mark.asyncio
async def test_integrations_and_crosswalk(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        sns = await client.get("/api/v1/banking/integrations/servicenow")
        qy = await client.get("/api/v1/banking/integrations/qualys")
        xw = await client.get("/api/v1/banking/compliance-crosswalk")
    assert sns.status_code == 200 and sns.json()["count"] >= 2
    assert qy.status_code == 200 and qy.text.startswith("ASSET,TYPE,SERVICE")
    body = xw.json()
    assert any(c["iso27001"] for c in body["controls"])
    assert body["trust_package"]["package"] == "procurement-trust-package"


@pytest.mark.asyncio
async def test_fips_lookup_and_registry(app_db, tmp_path, monkeypatch):
    reg = tmp_path / "fips.json"
    monkeypatch.setenv("CRYPTOSCAN_FIPS_REGISTRY", str(reg))
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        hit = await client.get("/api/v1/banking/fips", params={"module": "OpenSSL FIPS Provider 3.0"})
        miss = await client.get("/api/v1/banking/fips", params={"module": "unknown-lib"})
        add = await client.post("/api/v1/banking/fips/registry", json={
            "module": "Luna K7 Firmware", "vendor": "Thales", "standard": "FIPS 140-3", "cert": "XXXX"})
        listing = await client.get("/api/v1/banking/fips/registry")
    assert hit.status_code == 200 and hit.json()["cert"] == "4282"
    assert miss.json()["status"] == "unknown" and "CMVP" in miss.json()["note"]
    assert add.status_code == 200 and add.json()["ok"] is True
    modules = {e["module"] for e in listing.json()["entries"]}
    assert "luna k7 firmware" in modules


# --------------------------------------------------------------------------- #
# International: jurisdictions, SWIFT CSP, key lifecycle, multi-language export
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_jurisdictions_list_and_detail(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        listing = await client.get("/api/v1/banking/jurisdictions")
        eu = await client.get("/api/v1/banking/jurisdiction/eu?institution=Test%20Bank")
        bad = await client.get("/api/v1/banking/jurisdiction/atlantis")
    assert listing.status_code == 200 and listing.json()["count"] >= 10
    body = eu.json()
    assert body["pack"]["code"] == "eu"
    assert body["action_plan"]["jurisdiction"] == "eu"
    assert any("DORA" in m["label"] for m in body["action_plan"]["milestones"])
    assert any("ECB" in ref for ref in body["action_plan"]["references"])
    assert bad.status_code == 404


@pytest.mark.asyncio
async def test_uae_jurisdiction_and_cbuae_framework(app_db):
    """The UAE pack carries CBUAE/DIFC/PDPL/ADGM milestones and drives a
    cbuae-framework action plan (supervisor-ready, en/ar)."""
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        ae = await client.get("/api/v1/banking/jurisdiction/ae")
        plan = await client.get("/api/v1/banking/action-plan?framework=cbuae")
        bad = await client.get("/api/v1/banking/action-plan?framework=madeup")
        ar = await client.get("/api/v1/banking/action-plan/export?format=html&lang=ar&jurisdiction=ae")
    pack = ae.json()["pack"]
    assert pack["code"] == "ae" and pack["framework"] == "cbuae"
    assert pack["languages"] == ["en", "ar"]
    labels = " ".join(m["label"] for m in pack["milestones"])
    assert "DIFC" in labels and "PDPL" in labels and "CBUAE" in labels and "ADGM" in labels
    dated = [m["date"] for m in pack["milestones"] if m.get("date")]
    assert "2020-07-01" in dated and "2022-01-02" in dated and "2025-07-01" in dated
    refs = ae.json()["action_plan"]["references"]
    assert refs and any("DIFC" in r for r in refs)
    assert plan.status_code == 200 and plan.json()["framework"] == "cbuae"
    assert bad.status_code == 422
    assert ar.status_code == 200 and 'dir="rtl"' in ar.text and "CBUAE" in ar.text


@pytest.mark.asyncio
async def test_action_plan_export_language_and_jurisdiction(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        de = await client.get("/api/v1/banking/action-plan/export?format=html&lang=de&jurisdiction=eu")
        ar = await client.get("/api/v1/banking/action-plan/export?format=html&lang=ar")
        badlang = await client.get("/api/v1/banking/action-plan/export?format=html&lang=klingon")
    assert de.status_code == 200 and "Maßnahmenplan" in de.text
    assert ar.status_code == 200 and 'dir="rtl"' in ar.text
    assert badlang.status_code == 422


@pytest.mark.asyncio
async def test_key_lifecycle_endpoint_from_ingest(app_db):
    icsf = ("LABEL,ALGORITHM,KEYBITS,USAGE,STATUS\n"
            "PAY.ZEK.2026,AES,256,CIPHER,ACTIVE\n"
            "OLD.MAC.DES,DES,56,MAC,COMPROMISED\n")
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        await client.post("/api/v1/banking/mainframe/ingest",
                          json={"kind": "icsf_csv", "content": icsf})
        keys = await client.get("/api/v1/banking/keys?source=icsf")
    assert keys.status_code == 200
    body = keys.json()
    assert body["total"] == 2
    assert body["by_state"] == {"compromised": 1, "active": 1}
    assert body["keys"][0]["state"] == "compromised"          # sorted first
    assert body["keys"][0]["label"] == "OLD.MAC.DES"
    assert body["standard"].startswith("NIST SP 800-57")


@pytest.mark.asyncio
async def test_swift_csp_endpoint(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        resp = await client.get("/api/v1/banking/swift-csp")
    assert resp.status_code == 200
    cscf = resp.json()["cscf"]
    assert cscf["programme"].startswith("SWIFT")
    assert len(cscf["controls"]) == 6
    assert isinstance(cscf["attestation_ready"], bool)


# --------------------------------------------------------------------------- #
# Group governance — entities, rollup, DORA register
# --------------------------------------------------------------------------- #

VALID_LEI_BODY = "BANKDE123456"


def _lei(body: str = VALID_LEI_BODY) -> str:
    cs = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b = body.upper().ljust(18, "X")[:18]
    n = int("".join(str(cs.index(c)) for c in b) + "00")
    return b + f"{98 - (n % 97):02d}"


@pytest.mark.asyncio
async def test_group_entity_registry_crud(app_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_GROUP_ENTITIES", str(tmp_path / "entities.json"))
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        add = await client.post("/api/v1/banking/group/entities", json={
            "code": "de-ret", "name": "Musterbank Retail AG", "jurisdiction": "eu",
            "lei": _lei(), "country": "de"})
        bad_lei = await client.post("/api/v1/banking/group/entities", json={
            "code": "fr-ret", "name": "X", "jurisdiction": "eu", "lei": "BANKXXXXXXXXXXXXXXXX99"})
        listing = await client.get("/api/v1/banking/group/entities")
        deleted = await client.delete("/api/v1/banking/group/entities/de-ret")
        gone = await client.delete("/api/v1/banking/group/entities/de-ret")
    assert add.status_code == 200 and add.json()["ok"] is True
    assert bad_lei.status_code == 422
    body = listing.json()
    assert body["count"] == 1 and body["entities"][0]["code"] == "de-ret"
    assert deleted.status_code == 200 and gone.status_code == 404


@pytest.mark.asyncio
async def test_group_rollup_assigns_and_aggregates(app_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_GROUP_ENTITIES", str(tmp_path / "entities.json"))
    # group test needs a system + an asset mapping (fixture ships assets only)
    from db.models import System as SystemModel, SystemAsset as SystemAssetModel
    session = app_db.state.test_session
    session.add(SystemModel(id="sys-web", name="web-frontend", owner="platform"))
    session.add(SystemAssetModel(system_id="sys-web", asset_id="ca-aes"))
    session.commit()
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        await client.post("/api/v1/banking/group/entities", json={
            "code": "de-ret", "name": "Retail AG", "jurisdiction": "eu"})
        # sys-web carries ca-aes (AES-256); assign it to the entity
        assign = await client.put("/api/v1/banking/group/systems/sys-web/entity",
                                  json={"entity_code": "de-ret"})
        unknown = await client.put("/api/v1/banking/group/systems/sys-web/entity",
                                   json={"entity_code": "nope"})
        roll = await client.get("/api/v1/banking/group")
    assert assign.status_code == 200 and assign.json()["legal_entity"] == "de-ret"
    assert unknown.status_code == 422
    body = roll.json()
    assert body["registry_count"] == 1
    ent = body["entities"][0]
    assert ent["entity"]["code"] == "de-ret"
    assert ent["systems"] == 1 and ent["crypto_instances"] == 1  # sys-web → ca-aes
    assert body["unassigned_systems"] == 0                        # the only system is assigned
    assert body["group"]["totals"]["entities"] == 1


@pytest.mark.asyncio
async def test_dora_register_json_and_csv(app_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_GROUP_ENTITIES", str(tmp_path / "entities.json"))
    from db.models import Vendor as VendorModel
    import datetime as _dt
    session = app_db.state.test_session
    session.add(VendorModel(id="v-thales", name="Thales", vendor_type="hsm",
                            criticality="MISSION-CRITICAL",
                            contract_end_date=_dt.datetime(2026, 10, 1)))
    session.commit()
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        await client.post("/api/v1/banking/group/entities", json={
            "code": "de-ret", "name": "Retail AG", "jurisdiction": "eu"})
        js = await client.get("/api/v1/banking/group/dora-register?entity=de-ret")
        csv_resp = await client.get("/api/v1/banking/group/dora-register?format=csv&entity=de-ret")
    assert js.status_code == 200
    body = js.json()
    assert body["total"] == 1 and body["entity_code"] == "de-ret"
    assert body["rows"][0]["provider_name"] == "Thales"
    assert body["critical"] == 1 and body["critical_expiring_180d"] == 1
    assert body["rows"][0]["bank_to_supply"]                      # honest placeholders
    assert csv_resp.status_code == 200
    assert csv_resp.text.startswith("provider_name,ict_service_type")


@pytest.mark.asyncio
async def test_group_entity_delete_unknown_404(app_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_GROUP_ENTITIES", str(tmp_path / "entities.json"))
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        r = await client.delete("/api/v1/banking/group/entities/ghost")
    assert r.status_code == 404


# --- supervisory portal (supervision.read-gated) -----------------------------

def _mint_supervisor(session, username: str, roles: list[str]) -> str:
    """Real session token carrying ``roles`` (RBAC dependency resolves it)."""
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
    UserRepository(session).create_session(token, username, expires, ip="127.0.0.1")
    session.commit()
    return token


def _sup_headers(session, roles: list[str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {_mint_supervisor(session, 'sup-' + roles[0], roles)}"}


@pytest.mark.asyncio
async def test_group_roadmap_buckets_and_csv(app_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_GROUP_ENTITIES", str(tmp_path / "reg.json"))
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        r = await client.post("/api/v1/banking/group/entities",
                              headers=_sup_headers(app_db.state.test_session, ["supervisor"]),
                              json={"code": "bank-de", "name": "Bank DE",
                                    "jurisdiction": "de", "lei": _lei()})
        assert r.status_code in (200, 201), r.text
        # link a quantum-vulnerable asset (RSA-2048) into the entity estate
        s = app_db.state.test_session
        s.add(System(id="sys-pay", name="payments-core"))
        s.add(SystemAsset(system_id="sys-pay", asset_id="ca-rsa"))
        s.commit()
        sup = _sup_headers(app_db.state.test_session, ["supervisor"])
        assigned = await client.put("/api/v1/banking/group/systems/sys-pay/entity",
                                    headers=sup, json={"entity_code": "bank-de"})
        assert assigned.status_code == 200, assigned.text

        roadmap = await client.get("/api/v1/banking/group/roadmap", headers=sup)
        assert roadmap.status_code == 200
        body = roadmap.json()
        assert body["basis"].startswith("NIST IR 8547")
        rsa = [row for row in body["rows"] if row["family"] == "RSA-2048"]
        assert rsa and rsa[0]["bucket"] == "by-2030"
        assert rsa[0]["entity_code"] == "bank-de"
        assert rsa[0]["deadline"] == "2030-12-31"

        csv_resp = await client.get("/api/v1/banking/group/roadmap?format=csv",
                                    headers=_sup_headers(app_db.state.test_session, ["supervisor"]))
        assert csv_resp.status_code == 200
        assert csv_resp.headers["content-type"].startswith("text/csv")
        assert "attachment; filename=\"migration-roadmap-" in csv_resp.headers["content-disposition"]
        assert "RSA-2048" in csv_resp.text and "by-2030" in csv_resp.text


@pytest.mark.asyncio
async def test_supervisor_pack_assembles_sections(app_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_GROUP_ENTITIES", str(tmp_path / "reg.json"))
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        await client.post("/api/v1/banking/group/entities",
                          headers=_sup_headers(app_db.state.test_session, ["supervisor"]),
                          json={"code": "bank-de", "name": "Bank DE",
                                "jurisdiction": "de", "lei": _lei()})
        pack = await client.get("/api/v1/banking/group/supervisor-pack",
                                headers=_sup_headers(app_db.state.test_session, ["supervisor"]))
        assert pack.status_code == 200
        body = pack.json()
        inner = body["pack"]
        assert inner["pack"]["kind"] == "supervisory-pack"
        assert inner["entities"][0]["code"] == "bank-de"
        assert "migration_roadmap_summary" in inner and "dora_register_summary" in inner
        assert len(inner["declared_limits"]) == 3
        assert any("placeholders" in lim for lim in inner["declared_limits"])


@pytest.mark.asyncio
async def test_supervisory_surfaces_deny_non_supervisor_roles(app_db):
    headers = _sup_headers(app_db.state.test_session, ["readonly"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://t") as client:
        for path in ("/api/v1/banking/group/roadmap",
                     "/api/v1/banking/group/supervisor-pack"):
            denied = await client.get(path, headers=headers)
            assert denied.status_code == 403, path
            assert "supervision.read" in denied.json()["detail"]
        # unauthenticated is 401 from the dependency's token resolution
        anon = await client.get("/api/v1/banking/group/roadmap")
        assert anon.status_code == 401