"""W59-60 honest subset: hot-path indexes, response compression, estate CSV export."""

from __future__ import annotations

import csv
import io

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
    app.dependency_overrides[get_current_user] = lambda: "analyst"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed(session, count=30):
    from datetime import datetime, timezone

    session.add(
        Scan(id="scan-perf", scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
             target_location="https://github.com/org/big.git", target_type="GIT_REPOSITORY",
             status="COMPLETED", statistics={})
    )
    for index in range(count):
        session.add(
            EvidenceRecord(
                scan_id="scan-perf", content_hash=f"{index:064d}", chain_hash=f"{index:063d}a",
                chain_position=index, previous_hash=None,
                algorithm="MD5" if index % 2 else "AES-256-GCM",
                confidence="HIGH", purpose="HASHING" if index % 2 else "ENCRYPTION",
                mode=None, key_size=None, file_path=f"src/file{index}.py",
                line_number=index + 1, finding_data={"scanner_id": "s"},
                compliance_status="FAIL" if index % 2 else "PASS",
            )
        )
    session.flush()


def test_composite_indexes_exist_in_metadata_and_migration():
    """The hot-query composites are declared on the models (fresh DBs) …"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    names = {row[0] for row in engine.connect().exec_driver_sql(
        "select name from sqlite_master where type='index'"
    )}
    expected = {
        "ix_evidence_scan_chain",        # per-scan listing + chain verify
        "ix_evidence_scan_status",       # failing-findings per scan
        "ix_assets_algorithm_file",      # asset listing filter+order
        "ix_systems_agility_score",      # agility ranking
        "ix_migration_tasks_project_status",
    }
    assert expected <= names, f"missing: {expected - names}"

    # … and mirrored in migration 0026 for existing deployments
    from pathlib import Path

    migration = (
        Path(__file__).resolve().parents[3] / "database" / "migrations" / "versions" / "0026_query_indexes.py"
    )
    text = migration.read_text()
    assert all(name in text for name in expected)
    assert "create_index" in text


@pytest.mark.asyncio
async def test_findings_csv_export_filters_and_reports_honestly():
    app, session, engine = _make_app()
    _seed(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/export/findings.csv", params={"algorithm": "MD5"})
        assert response.status_code == 200
        assert response.headers["Content-Type"].startswith("text/csv")
        assert response.headers["X-Total-Matching"] == "15"
        assert response.headers["X-Exported-Rows"] == "15"
        assert response.headers["X-Truncated"] == "false"
        rows = list(csv.reader(io.StringIO(response.text)))
        assert rows[0][0] == "evidence_id"
        body = rows[1:]
        assert len(body) == 15
        assert all(row[2] == "MD5" for row in body)

        # truncation is reported, never silently dropped
        capped = await client.get("/api/v1/export/findings.csv", params={"limit": 5})
        assert capped.headers["X-Total-Matching"] == "30"
        assert capped.headers["X-Exported-Rows"] == "5"
        assert capped.headers["X-Truncated"] == "true"
        assert len(list(csv.reader(io.StringIO(capped.text)))) == 6  # header + 5

        # filters compose: failing MD5 only
        strict = await client.get(
            "/api/v1/export/findings.csv",
            params={"algorithm": "MD5", "compliance_status": "PASS"},
        )
        assert strict.headers["X-Total-Matching"] == "0"


@pytest.mark.asyncio
async def test_bulk_responses_are_gzipped():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        catalog = await client.get(
            "/api/v1/remediation/templates", headers={"Accept-Encoding": "gzip"}
        )
        assert catalog.status_code == 200
        assert len(catalog.content) > 1024  # only bulky payloads compress
        assert catalog.headers.get("content-encoding") == "gzip"
        # a client that refuses gzip never receives it (httpx asks by default)
        plain = await client.get(
            "/api/v1/remediation/templates", headers={"Accept-Encoding": "identity"}
        )
        assert plain.headers.get("content-encoding") != "gzip"
