"""CI gate endpoint: policy profiles + blocked-deployments recording."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan


def _make_app():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "ci-bot"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed(session):
    session.add_all(
        [
            Scan(
                id="scan-weak", scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
                target_location="https://github.com/org/legacy.git", target_type="GIT_REPOSITORY",
                status="COMPLETED", statistics={},
            ),
            Scan(
                id="scan-hash", scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
                target_location="https://github.com/org/util.git", target_type="GIT_REPOSITORY",
                status="COMPLETED", statistics={},
            ),
        ]
    )
    session.add_all(
        [
            EvidenceRecord(
                scan_id="scan-weak", content_hash="a" * 64, chain_hash="h" + "0" * 63,
                chain_position=0, previous_hash=None, algorithm="DES", confidence="HIGH",
                purpose="ENCRYPTION", mode=None, key_size=None,
                file_path="src/Pay.java", line_number=7, finding_data={"scanner_id": "s"},
                compliance_status="FAIL",
            ),
            EvidenceRecord(
                scan_id="scan-hash", content_hash="b" * 64, chain_hash="i" + "1" * 63,
                chain_position=0, previous_hash=None, algorithm="MD5", confidence="HIGH",
                purpose="HASHING", mode=None, key_size=None,
                file_path="src/Util.java", line_number=3, finding_data={"scanner_id": "s"},
                compliance_status="FAIL",
            ),
        ]
    )
    session.flush()


@pytest.mark.asyncio
async def test_profiles_change_blocking_not_findings():
    app, session, engine = _make_app()
    _seed(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # weak hash: WARN under standard semantics
        standard = (await client.post("/api/v1/ci/gate", json={"scan_id": "scan-hash", "profile": "standard"})).json()
        assert standard["decision"] == "WARN" and not standard["blocking"]
        assert standard["recorded"] is True

        # strict: the warning now blocks
        strict = (await client.post("/api/v1/ci/gate", json={"scan_id": "scan-hash", "profile": "strict"})).json()
        assert strict["decision"] == "FAIL" and len(strict["blocking"]) == 1
        assert strict["profile"] == "strict"

        # lenient: weak crypto is advisory; hardcoded keys/downgrades still block
        lenient = (await client.post("/api/v1/ci/gate", json={"scan_id": "scan-weak", "profile": "lenient"})).json()
        assert lenient["decision"] == "WARN" and lenient["blocking"] == []
        assert any(item["code"] == "WEAK_CRYPTO" for item in lenient["warnings"])

        missing = await client.post("/api/v1/ci/gate", json={"scan_id": "nope"})
        assert missing.status_code == 404

        bad_profile = await client.post("/api/v1/ci/gate", json={"scan_id": "scan-weak", "profile": "chaos"})
        assert bad_profile.status_code == 422  # unknown profile rejected at the boundary


@pytest.mark.asyncio
async def test_gate_evaluations_rollup_counts_blocked_deployments():
    app, session, engine = _make_app()
    _seed(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/ci/gate", json={"scan_id": "scan-hash", "profile": "standard"})  # WARN
        await client.post("/api/v1/ci/gate", json={"scan_id": "scan-hash", "profile": "strict"})    # FAIL
        await client.post("/api/v1/ci/gate", json={"scan_id": "scan-weak", "profile": "standard"})  # FAIL
        await client.post("/api/v1/ci/gate", json={"scan_id": "scan-weak", "profile": "standard"})  # FAIL

        stats = (await client.get("/api/v1/ci/gate-evaluations?days=30")).json()
        assert stats["evaluations"] == 4
        assert stats["blocked"] == 3
        assert stats["warned"] == 1
        assert stats["passed"] == 0
        assert stats["profiles"] == {"standard": 3, "strict": 1}
        top = stats["by_repo"][0]
        assert top["repo"] == "https://github.com/org/legacy.git" and top["blocked"] == 2


@pytest.mark.asyncio
async def test_report_templates_endpoint():
    app, session, engine = _make_app()
    _seed(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        listing = (await client.get("/api/v1/report-templates")).json()
        ids = {row["id"] for row in listing["templates"]}
        assert {"pci-dss-4.0", "custom", "soc2"} <= ids

        # DES ENCRYPTION FAIL trips forbidden-algorithm rules; the PCI
        # evaluation must carry the requirement table + attestation + hash
        report = (await client.get("/api/v1/scans/scan-weak/report?template=pci-dss-4.0")).json()
        assert "template_evaluation" in report and "report_hash" in report
        assert report["attestation"]["scan_id"] == "scan-weak"
        assert report["attestation"]["policy_pack_hash"]  # real pack hash attached

        custom = (
            await client.get("/api/v1/scans/scan-weak/report?template=custom&requirements=4.2.1,CC6.1")
        ).json()
        assert [r["id"] for r in custom["template_evaluation"]["requirements"]] == ["4.2.1", "CC6.1"]

        bad = await client.get("/api/v1/scans/scan-weak/report?template=chaos")
        assert bad.status_code == 400

        import re as _re

        html = await client.get("/api/v1/scans/scan-weak/report.html?template=pci-dss-4.0")
        assert html.status_code == 200
        # each rendered report is its own instance (fresh generated_at), so
        # verify the page carries its own well-formed hash + attestation
        assert "Report hash (SHA-256" in html.text and "Attestation:" in html.text
        assert _re.search(r"[0-9a-f]{64}", html.text)
