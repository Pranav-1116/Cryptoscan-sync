"""Materialized views: the snapshot equals the truth at refresh time, and
the refresh never blocks the dashboards reading the previous one."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
for extra in ("services/database", "shared/shared_models", "shared/shared_config",
              "shared/shared_logging", "services/api"):
    if str(ROOT / extra) not in sys.path:
        sys.path.insert(0, str(ROOT / extra))

pgserver = pytest.importorskip("pgserver",
                               reason="pgserver is not installed: no PostgreSQL to refresh")
MIGRATIONS = ROOT / "services" / "database" / "migrations"


@pytest.fixture(scope="module")
def migrated_engine():
    from sqlalchemy import create_engine

    work = tempfile.mkdtemp(prefix="pg-matview-")
    server = pgserver.get_server(work)
    uri = server.get_uri()
    server.psql("CREATE DATABASE cryptoscan;")
    host = uri.split("host=")[1]
    url = f"postgresql+psycopg2://postgres:@/cryptoscan?host={host}"
    env = dict(os.environ)
    env["DATABASE_URL"] = url
    env["PYTHONPATH"] = ":".join(
        [str(ROOT / extra) for extra in
         ("services/database", "shared/shared_models", "shared/shared_config",
          "shared/shared_logging", "services/api")] + [env.get("PYTHONPATH", "")])
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
        cwd=str(MIGRATIONS), env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        server.cleanup()
        pytest.fail("migration chain does not reach head:\n" + proc.stderr[-3000:])
    engine = create_engine(url, future=True)
    try:
        yield engine
    finally:
        engine.dispose()
        server.cleanup()


def _seed(engine):
    from datetime import datetime, timezone

    from sqlalchemy.orm import sessionmaker

    from db.models.estate_catalog import EstateAssetRecord
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan

    session = sessionmaker(bind=engine)()
    try:
        now = datetime.now(timezone.utc)
        for tenant, asset, name, state in (
                ("t1", "a1", "one", "ACTIVE"), ("t1", "a2", "two", "ACTIVE"),
                ("t1", "a3", "three", "STALE"), ("t2", "b1", "four", "ACTIVE")):
            session.add(EstateAssetRecord(
                tenant_id=tenant, asset_id=asset, asset_type="APPLICATION",
                name=name, lifecycle_state=state))
        scan = Scan(scan_start=now, target_location="repo://seed")
        session.add(scan)
        session.flush()
        for position, verdict in enumerate(("PASS", "FAIL", "PENDING")):
            session.add(EvidenceRecord(
                tenant_id="t1", scan_id=scan.id,
                content_hash=f"h{position}", chain_hash=f"c{position}",
                chain_position=position, file_path="src/seed.py",
                line_number=position + 1, finding_data={},
                compliance_status=verdict))
        session.commit()
    finally:
        session.close()


class TestMaterializedViews:

    def test_the_snapshot_equals_the_truth_at_refresh_time(self, migrated_engine):
        from sqlalchemy import text

        from db.materialized import refresh_materialized_views

        _seed(migrated_engine)
        outcomes = refresh_materialized_views(migrated_engine)
        assert outcomes["mv_portfolio_summary"]["status"] == "refreshed"
        assert outcomes["mv_compliance_summary"]["status"] == "refreshed"

        with migrated_engine.connect() as conn:
            truth = conn.execute(text(
                "SELECT tenant_id, count(*) FROM estate_assets GROUP BY"
                " tenant_id ORDER BY tenant_id")).fetchall()
            snapshot = conn.execute(text(
                "SELECT tenant_id, assets_total FROM mv_portfolio_summary"
                " ORDER BY tenant_id")).fetchall()
            assert snapshot == truth, (
                "a materialized view that disagrees with its own GROUP BY "
                "is a dashboard that lies")

            compliance = conn.execute(text(
                "SELECT evidence_pass, evidence_fail, evidence_pending,"
                " evidence_total FROM mv_compliance_summary"
                " WHERE tenant_id = 't1'")).fetchone()
            assert compliance == (1, 1, 1, 3)

    def test_concurrent_refresh_never_blocks_and_is_legal(self, migrated_engine):
        from db.materialized import refresh_materialized_views

        for _ in range(3):
            outcomes = refresh_materialized_views(migrated_engine,
                                                  concurrently=True)
            assert all(o["status"] == "refreshed" for o in outcomes.values())

    def test_a_broken_view_is_reported_not_raised_past_the_others(self, migrated_engine):
        from sqlalchemy import text

        from db.materialized import refresh_materialized_views

        with migrated_engine.begin() as conn:
            conn.execute(text("DROP MATERIALIZED VIEW mv_compliance_summary"))
        outcomes = refresh_materialized_views(migrated_engine)
        assert outcomes["mv_portfolio_summary"]["status"] == "refreshed"
        assert outcomes["mv_compliance_summary"]["status"] == "absent"

    def test_sqlite_reports_absent_and_pretends_nothing(self):
        from db.connection.engine import create_db_engine
        from db.materialized import refresh_materialized_views

        engine = create_db_engine("sqlite://")
        try:
            outcomes = refresh_materialized_views(engine)
            for name, outcome in outcomes.items():
                assert outcome["status"] == "absent"
                assert "SQLite" in outcome["detail"]
        finally:
            engine.dispose()
