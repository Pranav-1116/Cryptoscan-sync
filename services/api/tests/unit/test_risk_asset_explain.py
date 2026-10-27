"""Asset-level risk explainability (§4.6, round 68).

Every row GET /risk/unified scores must be explainable at the SAME depth
the system-level chain has had since round 58: which inputs set each
factor level (and what level 0 MEANS), where the observation came from
(evidence joined on the identity spine), why controls fail (stored
verdicts), why PQC flags the asset (the real wave assignment) and who
owns it. Levels come from the same from_asset call — the explanation
cannot drift from the score it explains; the round-trip test below pins
that contract on the whole seeded estate.
"""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.config.settings import get_settings
from api.main import create_app
from db.connection.session import Base
from db.models import (
    BusinessProcess,
    Certificate,
    CloudAccount,
    CryptoAsset,
    System,
    SystemAsset,
    SystemBusinessProcess,
    User,
)
from db.models.evidence_record import EvidenceRecord


SECRET = "asset-risk-explain-test-" + "x" * 12


def _make_app():
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", SECRET)
    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(User(username="op", roles="developer", password_hash="x"))
    session.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "op"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed(session):
    """A small estate: a system, three crypto assets (DES joined to
    evidence, RSA joined + PQC-vulnerable, one with no locator), a decoy
    evidence row that must NOT join, a certificate and a cloud account."""
    session.add(System(
        id="sys-x", name="card-payments", environment="prod", criticality="TIER-1",
        cloud_provider="AWS", last_scan_id="scan-x", owner="payments-team",
        technical_owner="alice", security_owner="bob",
    ))
    ev = EvidenceRecord(
        scan_id="scan-x", content_hash="c" * 64, chain_hash="h" * 64, chain_position=0,
        algorithm="DES", purpose="ENCRYPTION", key_size=64, mode="CBC",
        confidence="HIGH", file_path="src/F0.java", line_number=1,
        compliance_status="FAIL", finding_data={},
        policy_evaluation={"rules_evaluated": [
            {"rule_id": "BASE-001", "rule_name": "No DES", "evaluation_result": "FAIL",
             "severity": "HIGH", "message": "DES is deprecated",
             "remediation": "Replace with AES-256-GCM"},
        ]},
    )
    session.add(ev)
    # same algorithm, DIFFERENT locator — must never join to the DES asset
    session.add(EvidenceRecord(
        scan_id="scan-x", content_hash="d" * 64, chain_hash="h" * 64, chain_position=1,
        algorithm="DES", purpose="ENCRYPTION", key_size=64, mode="CBC",
        confidence="HIGH", file_path="other/path/X.java", line_number=9,
        compliance_status="FAIL", finding_data={},
    ))
    session.add(EvidenceRecord(
        scan_id="scan-x", content_hash="e" * 64, chain_hash="h" * 64, chain_position=2,
        algorithm="RSA", purpose="KEY_EXCHANGE", key_size=2048, mode=None,
        confidence="HIGH", file_path="src/K1.java", line_number=7,
        compliance_status="PASS", finding_data={},
    ))
    des = CryptoAsset(algorithm="DES", purpose="ENCRYPTION", key_size=64, mode="CBC",
                      file_path="src/F0.java", line_number=1, confidence="HIGH",
                      owner="payments-team")
    rsa = CryptoAsset(algorithm="RSA", purpose="KEY_EXCHANGE", key_size=2048,
                      file_path="src/K1.java", line_number=7, confidence="HIGH")
    # file_path is NOT NULL, but an EMPTY locator is representable — and
    # the spine deliberately refuses identity for a key without a WHERE.
    noloc = CryptoAsset(algorithm="AES-256-GCM", purpose="ENCRYPTION",
                        file_path="", confidence="LOW")
    session.add_all([des, rsa, noloc])
    session.flush()
    session.add(SystemAsset(system_id="sys-x", asset_id=des.id))
    session.add(Certificate(
        subject="CN=bank.example", issuer="CN=ca", public_key_algorithm="RSA",
        public_key_size=2048, expiry_status="VALID", fingerprint_sha256="f" * 64,
    ))
    session.add(CloudAccount(cloud_provider="AWS", account_identifier="1111"))
    process = BusinessProcess(name="Card Checkout", revenue_daily=1000.0)
    session.add(process)
    session.flush()
    session.add(SystemBusinessProcess(system_id="sys-x", process_id=process.id,
                                      role="PRIMARY"))
    session.commit()
    return {"des": des, "rsa": rsa, "noloc": noloc}


@pytest.mark.asyncio
async def test_every_unified_asset_explains_at_the_same_score():
    """Round-trip: each row /risk/unified scores has an explain with the
    SAME score/level/factor levels — the chain cannot drift from the
    score it explains."""
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        listing = await c.get("/api/v1/risk/unified?limit=200")
        assert listing.status_code == 200, listing.text
        assets = listing.json()["assets"]
        assert len(assets) >= 6  # system + 3 crypto + cert + cloud (+process)
        for a in assets:
            r = await c.get(f"/api/v1/risk/unified/{a['id']}/explain")
            assert r.status_code == 200, (a["id"], r.text)
            body = r.json()
            assert body["model"] == "asset-risk-explanation/v1"
            assert body["risk"]["score"] == a["score"]
            assert body["risk"]["level"] == a["level"]
            assert len(body["factors"]) == 8
            by_name = {f["factor"]: f for f in body["factors"]}
            for name, detail in a["factors"].items():
                assert by_name[name]["level"] == detail["level"], (a["id"], name)
                assert by_name[name]["points"] == detail["points"], (a["id"], name)
                assert by_name[name]["basis"] in {"DECLARED", "OBSERVED"}
                assert by_name[name]["derived_from"]["inputs"] is not None
            assert body["inventory_row"]["id"] == a["id"]


@pytest.mark.asyncio
async def test_crypto_factor_cites_the_matched_family_token():
    app, session, engine = _make_app()
    seeded = _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get(f"/api/v1/risk/unified/crypto:{seeded['des'].id}/explain")
    assert r.status_code == 200, r.text
    factors = {f["factor"]: f for f in r.json()["factors"]}
    crypto = factors["crypto"]
    assert crypto["level"] == 4
    assert crypto["derived_from"]["inputs"]["algorithm"] == "DES"
    assert "'DES'" in crypto["derived_from"]["rule"]
    assert "weak_or_legacy" in crypto["derived_from"]["rule"]
    # RSA: classical family → 2, and quantum-vulnerable → pqc 4
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get(f"/api/v1/risk/unified/crypto:{seeded['rsa'].id}/explain")
    factors = {f["factor"]: f for f in r.json()["factors"]}
    assert factors["crypto"]["level"] == 2
    assert factors["pqc"]["level"] == 4
    assert "quantum-vulnerable" in factors["pqc"]["derived_from"]["rule"]


@pytest.mark.asyncio
async def test_evidence_trail_joins_on_the_identity_spine_only():
    app, session, engine = _make_app()
    seeded = _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get(f"/api/v1/risk/unified/crypto:{seeded['des'].id}/explain")
    assert r.status_code == 200, r.text
    body = r.json()
    trail = body["evidence_trail"]
    assert trail["asset_key"], "spine key derived even when the row predates migration 0092"
    assert trail["total_observations"] == 1, "the decoy (same algorithm, other path) must not join"
    entry = trail["entries"][0]
    assert entry["location"] == "src/F0.java:1"
    assert entry["verify_path"] == "/api/v1/scans/scan-x/verify"
    assert entry["chain_position"] == 0
    # WHY the control fails — the stored verdict on the joined evidence
    controls = trail["failing_controls"]
    assert [c0["rule_id"] for c0 in controls] == ["BASE-001"]
    assert controls[0]["evidence_ids"] == [entry["evidence_id"]]
    assert body["accountability"]["systems_using"] == ["sys-x"]
    assert body["accountability"]["owner"] == "payments-team"


@pytest.mark.asyncio
async def test_asset_without_locator_says_so_never_fabricates_a_join():
    app, session, engine = _make_app()
    seeded = _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get(f"/api/v1/risk/unified/crypto:{seeded['noloc'].id}/explain")
    assert r.status_code == 200, r.text
    body = r.json()
    trail = body["evidence_trail"]
    assert trail["entries"] == []
    assert "no file locator" in trail["note"]
    assert any("identity spine" in lim for lim in body["limitations"])


@pytest.mark.asyncio
async def test_vulnerable_asset_gets_its_own_wave_assignment():
    app, session, engine = _make_app()
    seeded = _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get(f"/api/v1/risk/unified/crypto:{seeded['rsa'].id}/explain")
    assert r.status_code == 200, r.text
    pqc = r.json()["pqc_rationale"]
    assert pqc is not None
    assert pqc["vulnerable_sites"] >= 1
    site = pqc["sites"][0]
    assert site["algorithm"] == "RSA"
    assert site["recommended_replacement"], "the workstream target is the replacement"
    assert site["wave"]


@pytest.mark.asyncio
async def test_system_row_points_to_the_deeper_chain():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/risk/unified/system:sys-x/explain")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["system_explain_path"] == "/api/v1/risk/systems/sys-x/explain"
    assert any("deeper system chain" in lim for lim in body["limitations"])
    # declared factors still decompose honestly
    factors = {f["factor"]: f for f in body["factors"]}
    assert factors["exposure"]["level"] == 4  # prod
    assert factors["business_criticality"]["level"] == 4  # TIER-1
    assert factors["exposure"]["basis"] == "DECLARED"


@pytest.mark.asyncio
async def test_level_zero_is_explained_as_unknown_never_clean():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        listing = await c.get("/api/v1/risk/unified?limit=200")
        cloud = next(a for a in listing.json()["assets"]
                     if a["asset_type"] == "Cloud")
        r = await c.get(f"/api/v1/risk/unified/{cloud['id']}/explain")
    assert r.status_code == 200, r.text
    body = r.json()
    threat = next(f for f in body["factors"] if f["factor"] == "threat")
    assert threat["level"] == 0
    assert "UNKNOWN" in threat["derived_from"]["rule"]
    assert any("no threat feed" in lim for lim in body["limitations"])
    assert any("not 'internal'" in lim for lim in body["limitations"])


@pytest.mark.asyncio
async def test_unknown_asset_is_404_with_the_window_stated():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/risk/unified/crypto:nope/explain")
    assert r.status_code == 404
    assert "window" in r.json()["detail"].lower()
