"""Round-15 audit surfaces: retirement registry + reintroduction check,
asset lifecycle transitions, finding conflicts, evidence chain status.

One file because they share the seeding idiom; each section is independent.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.evidence_record import EvidenceRecord
from db.models.retired_asset import RetiredAsset
from db.models.scan import Scan

NOW = datetime.now(timezone.utc)


def _make_app(current_user: str = "auditor-1"):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    app.dependency_overrides[require_auditor] = lambda: current_user
    return app, session


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _scan(session, scan_id: str, when=None, status: str = "COMPLETED") -> Scan:
    row = Scan(id=scan_id, scan_start=when or NOW, scan_end=when or NOW,
               target_type="GIT_REPOSITORY", target_location=f"git@acme:{scan_id}.git",
               status=status)
    session.add(row)
    return row


def _evidence(session, eid: str, scan_id: str, algorithm: str, status: str = "FAIL",
              file_path: str = "src/pay/CardCipher.java", line: int = 42, **extra) -> EvidenceRecord:
    row = EvidenceRecord(id=eid, scan_id=scan_id, algorithm=algorithm,
                         compliance_status=status, file_path=file_path, line_number=line,
                         purpose=extra.get("purpose", "ENCRYPTION"),
                         key_size=extra.get("key_size"), mode=extra.get("mode"),
                         is_hardcoded_key=extra.get("is_hardcoded_key", False),
                         content_hash=f"hash-{eid}", chain_hash=f"chain-{eid}",
                         chain_position=1, confidence="HIGH", finding_data={})
    session.add(row)
    return row


# --------------------------------------------------------------------------- #
# retirement registry + reintroduction check (audit 69 / GAP-023)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_retirement_registry_lifecycle_and_check():
    app, session = _make_app()
    _scan(session, "scan-1", when=NOW - timedelta(hours=1))
    _evidence(session, "e1", "scan-1", "DES", status="FAIL")          # reintroduced
    _evidence(session, "e2", "scan-1", "AES-256-GCM", status="PASS")  # the replacement
    session.commit()

    async with _client(app) as client:
        # FILE scope without file_path is rejected
        bad = await client.post("/api/v1/retirements",
                                json={"algorithm": "DES", "scope": "FILE"})
        assert bad.status_code == 400

        created = await client.post("/api/v1/retirements", json={
            "algorithm": "des", "scope": "FILE",
            "file_path": "src/pay/CardCipher.java",
            "reason": "replaced after task t-9", "source_task_id": "t-9"})
        assert created.status_code == 200, created.text
        retirement = created.json()
        assert retirement["algorithm"] == "DES"  # normalized
        assert retirement["active"] is True

        listed = await client.get("/api/v1/retirements?active=true")
        assert listed.json()["count"] == 1

        check = await client.post("/api/v1/retirements/check/scan-1")
        assert check.status_code == 200, check.text
        body = check.json()
        assert body["retirements_checked"] == 1
        assert body["severity_counts"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0}
        detection = body["reintroductions"][0]
        assert detection["algorithm"] == "DES"
        assert detection["matched_sites"][0]["line_number"] == 42

        # lifting the retirement stops matching — the promise is cancelled
        lifted = await client.post(f"/api/v1/retirements/{retirement['id']}/lift",
                                   json={"reason": "approved exception EX-7"})
        assert lifted.status_code == 200
        assert lifted.json()["active"] is False
        recheck = await client.post("/api/v1/retirements/check/scan-1")
        assert recheck.json()["reintroductions"] == []

        # double-lift is a conflict
        again = await client.post(f"/api/v1/retirements/{retirement['id']}/lift",
                                  json={"reason": "again"})
        assert again.status_code == 409


@pytest.mark.asyncio
async def test_reintroduction_check_404_and_asset_scope():
    app, session = _make_app()
    async with _client(app) as client:
        assert (await client.post("/api/v1/retirements/check/nope")).status_code == 404

    # ASSET scope through the crypto-asset linkage
    _scan(session, "scan-2", when=NOW - timedelta(hours=1))
    _evidence(session, "e9", "scan-2", "RC4", status="WARN", file_path="src/X.java")
    session.add(CryptoAsset(id="asset-1", algorithm="RC4", file_path="src/X.java", line_number=1))
    session.add(CryptoAssetEvidence(asset_id="asset-1", evidence_id="e9"))
    session.add(RetiredAsset(
        algorithm="RC4", scope="ASSET", asset_id="asset-1", retired_by="auditor-1",
        retired_at=NOW - timedelta(days=1), active=True))
    session.commit()
    async with _client(app) as client:
        check = await client.post("/api/v1/retirements/check/scan-2")
        body = check.json()
        assert body["severity_counts"]["HIGH"] == 1
        assert body["reintroductions"][0]["scope"] == "ASSET"


# --------------------------------------------------------------------------- #
# crypto-asset lifecycle (audit 54)
# --------------------------------------------------------------------------- #

def _asset(session, asset_id: str = "asset-1", algorithm: str = "RSA-2048") -> CryptoAsset:
    row = CryptoAsset(id=asset_id, algorithm=algorithm, file_path="src/Pay.java", line_number=7)
    session.add(row)
    return row


@pytest.mark.asyncio
async def test_lifecycle_happy_path_and_rules():
    app, session = _make_app()
    _asset(session)
    session.commit()
    url = "/api/v1/inventory/assets/asset-1/lifecycle"
    async with _client(app) as client:
        # default state
        listed = await client.get("/api/v1/inventory/assets?lifecycle_state=DISCOVERED")
        assert any(a["id"] == "crypto:asset-1" for a in listed.json()["assets"])

        # illegal jump: DISCOVERED -> ACTIVE
        skip = await client.post(url, json={"to_state": "ACTIVE", "reason": "trust me"})
        assert skip.status_code == 409
        assert "Invalid transition DISCOVERED -> ACTIVE" in skip.json()["detail"]

        # legal path with reasons
        for state in ("VERIFIED", "ACTIVE", "DEPRECATED", "RETIRED"):
            step = await client.post(url, json={"to_state": state, "reason": f"moved to {state}"})
            assert step.status_code == 200, step.text
            assert step.json()["to_state"] == state

        # RETIRED is terminal
        resurrect = await client.post(url, json={"to_state": "ACTIVE", "reason": "it's back"})
        assert resurrect.status_code == 409
        assert "terminal" in resurrect.json()["detail"]


@pytest.mark.asyncio
async def test_lifecycle_unknown_asset_and_filter():
    app, session = _make_app()
    session.commit()
    async with _client(app) as client:
        missing = await client.post("/api/v1/inventory/assets/nope/lifecycle",
                                    json={"to_state": "VERIFIED", "reason": "x"})
        assert missing.status_code == 404


# --------------------------------------------------------------------------- #
# finding conflicts (audit 50)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_conflicts_within_and_between_scans():
    app, session = _make_app()
    _scan(session, "scan-1", when=NOW - timedelta(hours=2))
    _scan(session, "scan-2", when=NOW - timedelta(hours=1))
    # same site, two scanners, different algorithms
    _evidence(session, "a1", "scan-1", "RSA", key_size=2048, file_path="src/K.java", line=3)
    _evidence(session, "a2", "scan-1", "ECDSA", key_size=256, file_path="src/K.java", line=3)
    # between scans: same site, key size shrank
    _evidence(session, "b1", "scan-1", "RSA", key_size=2048, file_path="src/R.java", line=9)
    _evidence(session, "b2", "scan-2", "RSA", key_size=1024, file_path="src/R.java", line=9)
    session.commit()

    async with _client(app) as client:
        within = await client.get("/api/v1/findings/conflicts?scan_id=scan-1")
        assert within.status_code == 200, within.text
        body = within.json()
        assert body["by_type"] == {"ALGORITHM_MISMATCH": 1}
        conflict = body["conflicts"][0]
        assert conflict["file_path"] == "src/K.java"
        assert set(conflict["observers"]) == {"unknown-observer"} or conflict["observers"]

        between = await client.get(
            "/api/v1/findings/conflicts?scan_id=scan-1&compare_scan_id=scan-2")
        body = between.json()
        # the K.java algorithm disagreement persists in the union, and the
        # key-size shrink at R.java is a scan-vs-scan parameter conflict
        assert body["by_type"] == {"ALGORITHM_MISMATCH": 1, "PARAMETER_MISMATCH": 1}
        param = next(c for c in body["conflicts"]
                     if c["conflict_type"] == "PARAMETER_MISMATCH")
        assert param["file_path"] == "src/R.java"
        assert param["baseline_scan_id"] == "scan-1"
        assert param["current_scan_id"] == "scan-2"

        assert (await client.get("/api/v1/findings/conflicts?scan_id=nope")).status_code == 404
        assert (await client.get(
            "/api/v1/findings/conflicts?scan_id=scan-1&compare_scan_id=nope")).status_code == 404


# --------------------------------------------------------------------------- #
# evidence chain status (audit 14 TD-010)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_chain_status_reports_valid_and_broken():
    import hashlib

    from evidence.hashing.chain_hasher import ChainHasher
    from evidence.hashing.content_hasher import ContentHasher

    app, session = _make_app()

    def _seed_valid(scan_id: str):
        evidence_ids = [f"{scan_id}-e1", f"{scan_id}-e2"]
        _scan(session, scan_id, status="COMPLETED")
        session.execute(
            Scan.__table__.update().where(Scan.id == scan_id).values(
                manifest_hash=hashlib.sha256(
                    "".join(sorted(evidence_ids)).encode()).hexdigest()))
        previous = None
        for index, (eid, algo, path, line) in enumerate((
                (evidence_ids[0], "RSA-2048", "src/Pay.java", 7),
                (evidence_ids[1], "AES-256", "src/Seal.java", 9))):
            finding = {"scanner_id": "s", "source": {"file_path": path, "line_number": line},
                       "crypto": {"algorithm": algo}, "metadata": {"confidence": "HIGH"}}
            digest = ContentHasher.compute_hash(finding)
            chain = ChainHasher.compute_chain_hash(
                digest, previous_chain_hash=previous,
                scan_session_id=scan_id if index == 0 else None)
            session.add(EvidenceRecord(
                id=eid, scan_id=scan_id, content_hash=digest, chain_hash=chain,
                chain_position=index, previous_hash=previous, algorithm=algo,
                confidence="HIGH", file_path=path, line_number=line,
                finding_data=finding, compliance_status="PASS"))
            previous = chain

    _seed_valid("scan-good")
    # a scan whose chain is broken after the fact
    _seed_valid("scan-bad")
    session.flush()
    bad_row = session.execute(
        EvidenceRecord.__table__.select().where(
            EvidenceRecord.__table__.c.id == "scan-bad-e2")
    ).mappings().first()
    session.execute(
        EvidenceRecord.__table__.update().where(
            EvidenceRecord.__table__.c.id == "scan-bad-e2").values(
            finding_data={**bad_row["finding_data"], "crypto": {"algorithm": "TAMPERED"}}))
    session.commit()

    async with _client(app) as client:
        response = await client.get("/api/v1/ops/evidence/chain-status?limit=10")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["scans_checked"] == 2
        assert body["chains_valid"] == 1
        assert body["broken_scan_ids"] == ["scan-bad"]
        bad = next(r for r in body["results"] if r["scan_id"] == "scan-bad")
        assert bad["content_intact"] is False
        assert bad["result"] == "FAIL"
