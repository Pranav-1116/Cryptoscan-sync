"""Migration 0165: one live agent per (tenant, name) — case-insensitive,
NULL tenants collide, retired names are reusable, existing duplicates refuse."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

ROOT = Path(__file__).resolve().parents[3]


def _migration():
    path = (ROOT / "services" / "database" / "migrations" / "versions" /
            "0165_agent_unique_live_name.py")
    spec = importlib.util.spec_from_file_location("migration_0165", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine, fn):
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()


def _engine(*rows):
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(sa.text(
            "CREATE TABLE cp_agents (id VARCHAR(36) PRIMARY KEY, tenant_id VARCHAR(36),"
            " name VARCHAR(200) NOT NULL, status VARCHAR(20) NOT NULL)"))
        for i, (tenant, name, status) in enumerate(rows):
            _insert(conn, f"a{i}", tenant, name, status)
    return engine


def _has_index(engine) -> bool:
    with engine.connect() as conn:
        return conn.execute(sa.text(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='uq_cp_agents_live_name'")).first() is not None


def _insert(conn, agent_id, tenant, name, status="connected"):
    conn.execute(sa.text("INSERT INTO cp_agents VALUES (:i, :t, :n, :s)"),
                 {"i": agent_id, "t": tenant, "n": name, "s": status})


def test_live_names_are_unique_per_tenant_case_insensitive():
    engine = _engine((None, "mrdn-prod-dc1-swiftgw01", "connected"))
    _run(engine, _migration().upgrade)
    with pytest.raises(sa.exc.IntegrityError):
        with engine.begin() as conn:  # NULL tenant collides with NULL tenant
            _insert(conn, "dup", None, "MRDN-PROD-DC1-SWIFTGW01")
    with engine.begin() as conn:
        _insert(conn, "t1", "tenant-1", "mrdn-prod-dc1-swiftgw01")  # other tenant: fine
    with pytest.raises(sa.exc.IntegrityError):
        with engine.begin() as conn:
            _insert(conn, "t1b", "tenant-1", "mrdn-prod-dc1-swiftgw01")


def test_retired_name_can_be_enrolled_again():
    engine = _engine((None, "mrdn-prod-dc1-ibank01", "retired"),
                     (None, "mrdn-prod-dc1-ibank01", "retired"))
    _run(engine, _migration().upgrade)
    with engine.begin() as conn:
        _insert(conn, "new", None, "mrdn-prod-dc1-ibank01", "enrolled")


def test_existing_live_duplicates_refuse_and_delete_nothing():
    engine = _engine((None, "mrdn-prod-dc1-coredb01", "connected"),
                     (None, "Mrdn-Prod-DC1-CoreDB01", "offline"))
    with pytest.raises(RuntimeError, match="retire all but one"):
        _run(engine, _migration().upgrade)
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM cp_agents")).scalar() == 2
    assert not _has_index(engine)


def test_upgrade_is_idempotent_and_downgrade_drops():
    migration = _migration()
    engine = _engine()
    _run(engine, migration.upgrade)
    assert _has_index(engine)
    _run(engine, migration.upgrade)  # create_all installs already carry the index
    _run(engine, migration.downgrade)
    assert not _has_index(engine)
    with engine.begin() as conn:  # enforcement gone, nothing deleted
        _insert(conn, "x", None, "same")
        _insert(conn, "y", None, "same")


def test_model_declares_the_same_index():
    from db.models.control_plane import Agent

    engine = sa.create_engine("sqlite://")
    Agent.__table__.create(engine)
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO cp_agents (id, name, platform, status, healthy, link,"
            " offline_events_buffered) VALUES ('a', 'Host01', 'linux', 'connected', 0,"
            " 'disconnected', 0)"))
    with pytest.raises(sa.exc.IntegrityError):
        with engine.begin() as conn:
            conn.execute(sa.text(
                "INSERT INTO cp_agents (id, name, platform, status, healthy, link,"
                " offline_events_buffered) VALUES ('b', 'host01', 'linux', 'enrolled', 0,"
                " 'disconnected', 0)"))
