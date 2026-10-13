"""Round 19 (reports 49/55/58/64): system-level unified risk, configurable
weights via the risk engine, exposure-path queries, and system ownership
fields with audited changes."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.crypto_asset import CryptoAsset
from db.models.drift_event import DriftEvent
from db.models.evidence_record import EvidenceRecord
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from db.models.user import User
from db.models.vulnerability import Vulnerability

SECRET = "round19-test-secret-" + "x" * 16


def _make_app(current_user="op-user"):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", SECRET)
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(User(username="op-user", roles="developer", password_hash="x"))
    session.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed_risk_system(session):
    """A prod TIER-1 cloud system with DES + RSA evidence, drift, and a CVE."""
    session.add(System(
        id="sys-risk", name="payments-risk", environment="prod", criticality="TIER-1",
        cloud_provider="AWS", scan_target="https://github.com/org/payments.git",
        last_scan_id="scan-risk", owner="payments-team",
        technical_owner="alice", security_owner="bob",
    ))
    session.add(System(id="sys-empty", name="empty-system", last_scan_id=None))
    for i, (alg, status, conf) in enumerate(
        [("DES", "FAIL", "HIGH"), ("RSA-2048", "PASS", "HIGH")]
    ):
        session.add(EvidenceRecord(
            scan_id="scan-risk", content_hash=f"c{i}" * 32, chain_hash=f"h{i}" * 32,
            chain_position=i, previous_hash=None, algorithm=alg,
            confidence=conf, key_size=2048, file_path=f"src/F{i}.java", line_number=i + 1,
            finding_data={"scanner_id": "s"}, compliance_status=status,
        ))
    session.add(DriftEvent(
        current_scan_id="scan-risk", detected_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
        drift_type="ALGORITHM", severity="HIGH", resolution_status="OPEN",
    ))
    session.add(Vulnerability(
        cve="CVE-2026-0001", package="openssl", severity="CRITICAL", scan_id="scan-risk",
    ))
    session.commit()


@pytest.fixture
def risk_client():
    app, session, engine = _make_app()
    _seed_risk_system(session)
    yield AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    engine.dispose()


# --------------------------------------------------------------------- #
# Report 64 — system-level unified risk
# --------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_system_risk_derives_all_eight_factors(risk_client):
    resp = await risk_client.get("/api/v1/risk/systems/sys-risk")
    assert resp.status_code == 200
    data = resp.json()
    levels = data["levels"]
    assert levels["crypto"] == 4          # DES is DISALLOWED
    assert levels["pqc"] == 3             # 1 of 2 rows quantum-vulnerable
    assert levels["technical"] == 3       # drift HIGH beats fail-ratio level 2
    assert levels["exposure"] == 4        # prod environment
    assert levels["business_criticality"] == 4  # TIER-1
    assert levels["dependency_impact"] == 0
    assert levels["evidence_confidence"] == 4   # HIGH rows
    assert levels["threat"] == 4          # CRITICAL CVE
    assert data["level"] == "CRITICAL"
    assert data["calculation_version"] == "unified-risk-v1"
    assert data["weights_source"] == "default"
    assert data["evidence_count"] == 2
    assert data["open_drift_events"] == 1
    assert data["vulnerability_count"] == 1
    # accountability travels with the decomposition (round 42, §4.6)
    assert data["owner"] == "payments-team"
    assert data["technical_owner"] == "alice"
    assert data["security_owner"] == "bob"
    # unassigned owners are honest nulls, not invented names
    empty = (await risk_client.get("/api/v1/risk/systems/sys-empty")).json()
    assert empty["owner"] is None
    # raw derivation signals are exposed — the decomposition is self-describing
    assert data["signals"]["fail_ratio"] == 0.5
    assert data["signals"]["unknown_algorithms"] == 0
    assert data["signals"]["outgoing_dependencies"] == 0
    assert data["signals"]["environment"] == "prod"
    # decomposition present — response is its own audit trail
    assert set(data["factors"]) == set(levels)
    for factor in data["factors"].values():
        assert {"level", "points", "weight"} <= set(factor)


@pytest.mark.asyncio
async def test_system_risk_without_data_is_low_and_honest(risk_client):
    resp = await risk_client.get("/api/v1/risk/systems/sys-empty")
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 0.0
    assert data["level"] == "LOW"
    assert data["evidence_count"] == 0
    assert all(v == 0 for v in data["levels"].values())


@pytest.mark.asyncio
async def test_system_risk_unknown_system_404(risk_client):
    resp = await risk_client.get("/api/v1/risk/systems/nope")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_systems_ranked_list_with_estate_rollup(risk_client):
    resp = await risk_client.get("/api/v1/risk/systems")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    scores = [s["score"] for s in data["systems"]]
    assert scores == sorted(scores, reverse=True)
    assert data["systems"][0]["system_id"] == "sys-risk"
    assert data["estate"]["by_level"]["CRITICAL"] == 1
    assert data["estate"]["by_level"]["LOW"] == 1
    assert abs(sum(data["weights"].values()) - 1.0) < 1e-6
    assert data["weights_source"] == "default"


@pytest.mark.asyncio
async def test_env_weights_flow_into_system_risk(risk_client, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_RISK_WEIGHTS", '{"pqc": 1.0}')
    resp = await risk_client.get("/api/v1/risk/systems/sys-risk")
    assert resp.status_code == 200
    data = resp.json()
    assert data["weights_source"] == "env:CRYPTOSCAN_RISK_WEIGHTS"
    assert data["factors"]["pqc"]["weight"] == 1.0
    # pqc alone now drives the score: level 3 -> 75.0
    assert data["score"] == 75.0


@pytest.mark.asyncio
async def test_unified_asset_risk_still_works(risk_client):
    resp = await risk_client.get("/api/v1/risk/unified")
    assert resp.status_code == 200
    data = resp.json()
    assert "assets" in data and "estate" in data and "factors" in data


# --------------------------------------------------------------------- #
# Report 58 — exposure path queries
# --------------------------------------------------------------------- #

@pytest.fixture
def exposure_client():
    app, session, engine = _make_app()
    # edge: cloud entry -> middle -> deep (holding DES asset); isolated non-entry
    session.add(System(id="sys-edge", name="public-edge", cloud_provider="AWS"))
    session.add(System(id="sys-mid", name="internal-mid", environment="dev"))
    session.add(System(id="sys-deep", name="internal-deep"))
    session.add(System(id="sys-island", name="island"))
    session.add(SystemDependency(parent_id="sys-edge", child_id="sys-mid", relation="depends-on"))
    session.add(SystemDependency(parent_id="sys-mid", child_id="sys-deep", relation="depends-on"))
    session.add(CryptoAsset(
        id="asset-des", algorithm="DES", purpose="ENCRYPTION", key_size=56,
        file_path="src/deep/Crypto.java", line_number=3, confidence="HIGH",
    ))
    session.add(CryptoAsset(
        id="asset-aes", algorithm="AES", mode="GCM", key_size=256, purpose="ENCRYPTION",
        file_path="src/deep/Aes.java", line_number=4, confidence="HIGH",
    ))
    session.add(SystemAsset(system_id="sys-deep", asset_id="asset-des"))
    session.add(SystemAsset(system_id="sys-deep", asset_id="asset-aes"))
    session.commit()
    yield AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    engine.dispose()


@pytest.mark.asyncio
async def test_exposure_path_entry_to_asset(exposure_client):
    resp = await exposure_client.get("/api/v1/exposure/paths?min_rank=3")
    assert resp.status_code == 200
    data = resp.json()
    assert data["path_count"] == 1
    path = data["paths"][0]
    assert path["entry_system"]["name"] == "public-edge"
    assert "cloud-hosted" in path["entry_system"]["reason"]
    assert [c["name"] for c in path["chain"]] == ["public-edge", "internal-mid", "internal-deep"]
    assert path["depth"] == 2
    assert path["asset"]["algorithm"] == "DES"
    assert path["asset"]["designation"] == "DISALLOWED"
    assert path["weakest_rank"] == 4


@pytest.mark.asyncio
async def test_exposure_path_algorithm_filter(exposure_client):
    resp = await exposure_client.get("/api/v1/exposure/paths?algorithm=AES")
    assert resp.status_code == 200
    data = resp.json()
    assert data["path_count"] == 1
    assert data["paths"][0]["asset"]["algorithm"] == "AES"


@pytest.mark.asyncio
async def test_exposure_path_no_assets_is_empty_not_error(exposure_client):
    resp = await exposure_client.get("/api/v1/exposure/paths?algorithm=MD5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["path_count"] == 0
    assert data["paths"] == []
    assert data["entry_candidate_count"] == 1  # only the cloud system
    assert "not scanned reachability" in data["heuristic"]  # honest-boundary text (round 31 extended it to declared chains)


@pytest.mark.asyncio
async def test_exposure_path_islands_not_entries(exposure_client):
    resp = await exposure_client.get("/api/v1/exposure/paths?min_rank=0")
    data = resp.json()
    entries = [e["name"] for e in data["entry_candidates"]]
    assert entries == ["public-edge"]  # no cloud/remote metadata on the others


# --------------------------------------------------------------------- #
# Report 55 — ownership fields + audited changes
# --------------------------------------------------------------------- #

@pytest.fixture
def ownership_client():
    app, session, engine = _make_app()
    session.add(System(id="sys-own", name="owned-system", owner="alice",
                       scan_target="https://github.com/org/owned.git"))
    session.commit()
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    client.session = session  # exposed for audit-log assertions
    yield client
    engine.dispose()


@pytest.mark.asyncio
async def test_create_system_with_ownership_roles(ownership_client):
    resp = await ownership_client.post("/api/v1/systems", json={
        "name": "new-system", "owner": "alice",
        "technical_owner": "bob", "security_owner": "carol",
    })
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert data["technical_owner"] == "bob"
    assert data["security_owner"] == "carol"


@pytest.mark.asyncio
async def test_ownership_change_is_audited(ownership_client):
    from db.models.user import AuditLog

    resp = await ownership_client.patch("/api/v1/systems/sys-own", json={
        "technical_owner": "dave", "security_owner": "erin",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["technical_owner"] == "dave"
    assert data["security_owner"] == "erin"

    session = ownership_client.session
    entries = list(session.execute(
        select(AuditLog).where(AuditLog.action == "system.ownership_change")
    ).scalars().all())
    assert len(entries) == 1
    detail = entries[0].detail
    assert '"technical_owner"' in detail and "dave" in detail
    assert "alice" not in detail  # owner field untouched -> not in the audit

    # persisted state survives
    resp2 = await ownership_client.get("/api/v1/systems/sys-own")
    assert resp2.json()["technical_owner"] == "dave"


@pytest.mark.asyncio
async def test_non_ownership_patch_not_audited_as_ownership(ownership_client):
    from db.models.user import AuditLog

    resp = await ownership_client.patch("/api/v1/systems/sys-own", json={
        "description": "just a description",
    })
    assert resp.status_code == 200
    session = ownership_client.session
    entries = list(session.execute(
        select(AuditLog).where(AuditLog.action == "system.ownership_change")
    ).scalars().all())
    assert entries == []


@pytest.mark.asyncio
async def test_ownership_same_value_not_audited(ownership_client):
    from db.models.user import AuditLog

    resp = await ownership_client.patch("/api/v1/systems/sys-own", json={
        "owner": "alice",  # unchanged
    })
    assert resp.status_code == 200
    session = ownership_client.session
    entries = list(session.execute(
        select(AuditLog).where(AuditLog.action == "system.ownership_change")
    ).scalars().all())
    assert entries == []
