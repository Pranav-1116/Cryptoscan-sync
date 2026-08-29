"""W51-52: remediation template library over the API — catalog, rendered fixes, fix branches."""

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
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "dev"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed(session):
    session.add(
        Scan(id="scan-rem", scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
             target_location="https://github.com/org/svc.git", target_type="GIT_REPOSITORY",
             status="COMPLETED", statistics={})
    )
    session.add(
        EvidenceRecord(
            id="ev-md5", scan_id="scan-rem", content_hash="a" * 64, chain_hash="b" * 64,
            chain_position=0, previous_hash=None, algorithm="MD5", confidence="HIGH",
            purpose="HASHING", mode=None, key_size=None, file_path="src/hash.py",
            line_number=42, finding_data={"scanner_id": "s"}, compliance_status="FAIL",
        )
    )
    session.add(
        EvidenceRecord(
            id="ev-hardcoded", scan_id="scan-rem", content_hash="c" * 64, chain_hash="d" * 64,
            chain_position=1, previous_hash=None, algorithm="AES", confidence="HIGH",
            purpose="ENCRYPTION", mode="GCM", key_size=256, file_path="src/keys.py",
            line_number=7, finding_data={"scanner_id": "s"}, compliance_status="FAIL",
            is_hardcoded_key=True,
        )
    )
    session.flush()


@pytest.mark.asyncio
async def test_template_catalog_lists_everything_honestly():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        body = (await client.get("/api/v1/remediation/templates")).json()
        # counts reported, not inflated: templates × language snippets + guides
        assert body["template_count"] == len(body["templates"]) >= 15
        assert body["snippet_count"] == body["template_count"] * 4  # 4 languages each
        assert set(body["languages"]) == {"python", "java", "javascript", "go"}
        assert set(body["guides"]) >= {"kms-migration", "pqc-hybrid", "tls-upgrade"}
        # detail view renders one language fully; unknown rule 404s
        detail = (await client.get("/api/v1/remediation/templates/replace-md5")).json()
        assert detail["before"] and detail["after"] and detail["testing"] and detail["references"]
        assert (await client.get("/api/v1/remediation/templates/nope")).status_code == 404


@pytest.mark.asyncio
async def test_scan_suggestions_render_fix_per_rule_and_language():
    app, session, engine = _make_app()
    _seed(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        body = (await client.get(
            "/api/v1/remediation/scans/scan-rem/suggestions", params={"language": "java"}
        )).json()
        assert body["language"] == "java"
        rules = {s["rule"] for s in body["suggestions"]}
        assert "replace-md5" in rules
        assert "remove-hardcoded-key" in rules  # hardcoded beats algorithm concerns, P0
        hardcoded = next(s for s in body["suggestions"] if s["rule"] == "remove-hardcoded-key")
        assert hardcoded["priority"] == "P0"
        assert hardcoded["fix"]["language"] == "java"
        assert "kmsClient" in hardcoded["fix"]["after"]
        # unknown scan 404s
        assert (await client.get("/api/v1/remediation/scans/nope/suggestions")).status_code == 404


@pytest.mark.asyncio
async def test_fix_branch_payload_is_advisory_and_complete():
    app, session, engine = _make_app()
    _seed(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        body = (await client.post(
            "/api/v1/remediation/fix-branch",
            json={"evidence_id": "ev-md5", "language": "go"},
        )).json()
        assert body["branch"].startswith("fix/")
        assert body["commit_message"] and body["pr_title"] and body["pr_body"]
        assert body["commands"][0].startswith("git checkout -b")
        assert "never pushes" in body["pr_body"].lower()  # advisory, not automation
        assert body["changes"][0]["file_path"] == "src/hash.py"
        assert body["changes"][0]["after"]  # go snippet rendered
        # unknown evidence 404s
        missing = await client.post(
            "/api/v1/remediation/fix-branch", json={"evidence_id": "nope", "language": "go"}
        )
        assert missing.status_code == 404
