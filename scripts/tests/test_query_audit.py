"""Query audit: the hot estate searches, proven to hit their composites.

The dashboard's most-polled queries (list_assets, list_relationships,
crypto_for) filter the tenant first and order by business columns. This
audit seeds a real migrated PostgreSQL (pgserver) at catalogue scale and
runs EXPLAIN over the exact query shapes ``services/api/api/estate_catalog.py``
builds, asserting each one is served by the composite index migration 0154
declared for it.

What this proves, precisely: **coverage** — with ``enable_seqscan=off`` the
planner must be able to serve the query from the named composite (index
columns matching the predicates and ORDER BY), which is deterministic. It
does not claim the cost-based planner always picks that index on a tiny
table; that choice depends on statistics the deployment's ANALYZE owns.
A composite that stops covering a query (a column dropped from the WHERE,
an ORDER BY reshaped) fails here first — that is the point.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for extra in ("services/database", "shared/shared_models", "shared/shared_config",
              "shared/shared_logging", "services/api"):
    if str(ROOT / extra) not in sys.path:
        sys.path.insert(0, str(ROOT / extra))

pgserver = pytest.importorskip("pgserver", reason="pgserver is not installed: no PostgreSQL to audit")

MIGRATIONS = ROOT / "services" / "database" / "migrations"

TENANTS = 20
ASSETS_PER_TENANT = 300
CRYPTO_PER_ASSET = 4
RELS_PER_TENANT = 250


@pytest.fixture(scope="module")
def audited():
    """A migrated PostgreSQL seeded to catalogue scale, plus its engine."""
    from sqlalchemy import create_engine, text

    work = tempfile.mkdtemp(prefix="pg-query-audit-")
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
    with engine.begin() as conn:
        for t in range(TENANTS):
            tenant = f"tenant-{t:03d}"
            conn.execute(text(
                "INSERT INTO estate_assets (id, created_at, updated_at, tenant_id,"
                " asset_id, asset_type, name, environment, owner, lifecycle_state,"
                " observation_count) VALUES "
                "(md5(random()::text || clock_timestamp()::text), now(), now(), :t, :aid, 'APPLICATION',"
                " :name, 'prod', 'payments', 'ACTIVE', 1)"),
                [{"t": tenant, "aid": f"{tenant}-a{i}", "name": f"svc-{i}-{tenant}"}
                 for i in range(ASSETS_PER_TENANT)])
            conn.execute(text(
                "INSERT INTO estate_relationships (id, created_at, updated_at,"
                " tenant_id, relationship_id, subject_id, subject_name, predicate,"
                " object_id, status, lifecycle_state, observation_count) VALUES "
                "(md5(random()::text || clock_timestamp()::text), now(), now(), :t, :rid, :sid, :sname,"
                " 'depends_on', 'db-core', 'ESTABLISHED', 'ACTIVE', 1)"),
                [{"t": tenant, "rid": f"{tenant}-r{i}", "sid": f"{tenant}-s{i}",
                  "sname": f"subject-{i}-{tenant}"} for i in range(RELS_PER_TENANT)])
            conn.execute(text(
                "INSERT INTO estate_crypto_assets (id, created_at, updated_at,"
                " tenant_id, artifact_id, asset_id, algorithm, usage_state,"
                " lifecycle_state, observation_count) VALUES "
                "(md5(random()::text || clock_timestamp()::text), now(), now(), :t, :aid, :asset,"
                " 'AES-256-GCM', 'SUPPORTED', 'ACTIVE', 1)"),
                [{"t": tenant, "aid": f"{tenant}-a{i}-c{c}",
                  "asset": f"{tenant}-a{i}"}
                 for i in range(ASSETS_PER_TENANT // 5)
                 for c in range(CRYPTO_PER_ASSET)])
    try:
        yield engine
    finally:
        engine.dispose()
        server.cleanup()


def _plan(engine, sql: str, params: dict) -> str:
    from sqlalchemy import text

    with engine.connect() as conn:
        conn.execute(text("SET enable_seqscan = off"))
        rows = conn.execute(text("EXPLAIN " + sql), params).fetchall()
    return "\n".join(row[0] for row in rows)


class TestHotSearchCoverage:

    def test_list_assets_base_query_is_served_by_its_composite(self, audited):
        plan = _plan(audited, (
            "SELECT * FROM estate_assets WHERE tenant_id = :t "
            "ORDER BY asset_type, name LIMIT 100"), {"t": "tenant-003"})
        assert "ix_estate_assets_tenant_type_name" in plan, plan
        assert "Sort" not in plan, (
            "the composite's column order matches the ORDER BY — a Sort step "
            "means the index stopped covering the query")

    def test_list_assets_environment_filter_is_served_by_its_composite(self, audited):
        plan = _plan(audited, (
            "SELECT * FROM estate_assets WHERE tenant_id = :t "
            "AND environment = 'prod' ORDER BY asset_type, name LIMIT 100"),
            {"t": "tenant-003"})
        assert ("ix_estate_assets_tenant_env_type_name" in plan
                or "ix_estate_assets_tenant_type_name" in plan), plan
        assert "Sort" not in plan, (
            "both composites cover this shape sort-free: the env-type one "
            "with environment in the index condition, the type one with it "
            "as a filter. Which is cheaper is statistics; that no sort of "
            "the tenant slice is needed is the contract.")

    def test_list_relationships_default_path_is_served(self, audited):
        plan = _plan(audited, (
            "SELECT * FROM estate_relationships WHERE tenant_id = :t "
            "AND status = 'ESTABLISHED' ORDER BY predicate, subject_name "
            "LIMIT 100"), {"t": "tenant-005"})
        assert ("ix_estate_rels_tenant_status_pred_subject" in plan
                or "ix_estate_rels_tenant_pred_subject" in plan), plan
        assert "Sort" not in plan

    def test_list_relationships_status_all_path_is_served(self, audited):
        plan = _plan(audited, (
            "SELECT * FROM estate_relationships WHERE tenant_id = :t "
            "ORDER BY predicate, subject_name LIMIT 100"), {"t": "tenant-005"})
        assert "ix_estate_rels_tenant_pred_subject" in plan, plan
        assert "Sort" not in plan

    def test_crypto_for_asset_is_served_by_its_composite(self, audited):
        plan = _plan(audited, (
            "SELECT * FROM estate_crypto_assets WHERE tenant_id = :t "
            "AND asset_id = :a ORDER BY usage_state, algorithm"), 
            {"t": "tenant-007", "a": "tenant-007-a1"})
        assert "ix_estate_crypto_tenant_asset_usage" in plan, plan
        assert "Sort" not in plan

    def test_the_catalogue_is_seeded_at_scale_so_the_audit_is_not_a_toytown(self, audited):
        from sqlalchemy import text

        with audited.connect() as conn:
            assets = conn.execute(text(
                "SELECT count(*) FROM estate_assets")).scalar()
            crypto = conn.execute(text(
                "SELECT count(*) FROM estate_crypto_assets")).scalar()
        assert assets >= TENANTS * ASSETS_PER_TENANT
        assert crypto >= TENANTS * (ASSETS_PER_TENANT // 5) * CRYPTO_PER_ASSET
