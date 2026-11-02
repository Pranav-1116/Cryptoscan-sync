"""Row-level security: the binder, and what it does when there is no policy.

Two claims are tested separately, because they fail separately:

* on SQLite — and on any PostgreSQL that has not run migration 0132 — the binder
  must do nothing. A hook that issues ``set_config`` against a database without
  the function is a boot failure in development for a control that only exists in
  production.
* on real PostgreSQL, a transaction started inside a tenant scope must carry that
  tenant in ``cryptoscan.tenant_id``, and one started outside a scope must carry
  the platform wildcard. ``set_config(..., true)`` is transaction-local, so a
  pooled connection must never inherit either.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]  # …/services/database/tests/unit/test_rls.py
for _relative in ("services/api", "services/database", "shared/shared_models",
                  "shared/shared_config", "shared/shared_logging"):
    sys.path.insert(0, str(ROOT / _relative))

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "rls-test-key-32-characters-long")

from db.rls import PLATFORM_WILDCARD, TENANT_SETTING, bind_connection, enforcement, install_rls_binder  # noqa: E402
from db.tenancy import platform_scope, tenant_scope  # noqa: E402


def _sqlite_engine():
    from sqlalchemy import create_engine

    return create_engine("sqlite://", future=True)


# --------------------------------------------------------------------- SQLite ---


def test_the_binder_is_inert_on_sqlite():
    engine = _sqlite_engine()
    install_rls_binder()
    from sqlalchemy.orm import Session

    with Session(engine) as session:
        with tenant_scope("tenant-alpha"):
            assert session.execute(__import__("sqlalchemy").text("SELECT 1")).scalar() == 1


def test_enforcement_reports_unsupported_rather_than_pretending():
    engine = _sqlite_engine()
    with engine.connect() as connection:
        report = enforcement(connection)
    assert report["supported"] is False
    assert report["binds_this_role"] is False
    assert "no row-level security" in report["reason"]


def test_binding_is_a_no_op_on_sqlite():
    engine = _sqlite_engine()
    with engine.connect() as connection:
        bind_connection(connection, "tenant-alpha")  # must not raise


# ----------------------------------------------------------------- PostgreSQL ---


def _postgres_engine():
    """A real PostgreSQL with migration 0132 applied, or skip."""
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from pg_qualification import postgres_server  # noqa: PLC0415
        import pgserver  # noqa: F401, PLC0415 — presence check
    except ImportError:  # pragma: no cover - optional development dependency
        pytest.skip("no PostgreSQL distribution (pip install pgserver)")

    import subprocess  # noqa: PLC0415

    from sqlalchemy import create_engine  # noqa: PLC0415

    with postgres_server() as server:
        if server is None:  # pragma: no cover - defensive
            pytest.skip("no PostgreSQL server available")
        env = dict(os.environ, DATABASE_URL=server["url"])
        env["PYTHONPATH"] = os.pathsep.join(str(ROOT / part) for part in (
            "services/api", "services/database", "shared/shared_models",
            "shared/shared_config", "shared/shared_logging"))
        applied = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "migrations/alembic.ini", "upgrade", "head"],
            cwd=ROOT / "services" / "database", env=env, capture_output=True, text=True, timeout=900)
        if applied.returncode != 0:  # pragma: no cover - reported, not silenced
            pytest.fail(f"migrations did not apply: {(applied.stderr or applied.stdout)[-600:]}")
        yield create_engine(server["url"], future=True)


@pytest.fixture(scope="module")
def postgres_engine():
    generator = _postgres_engine()
    try:
        yield next(generator)
    except StopIteration:  # pragma: no cover - skip path
        return
    finally:
        generator.close()


def test_the_setting_is_bound_per_transaction(postgres_engine):
    from sqlalchemy import text
    from sqlalchemy.orm import Session

    install_rls_binder()
    with Session(postgres_engine) as session:
        with tenant_scope("11111111-1111-1111-1111-111111111111"):
            assert session.execute(
                text(f"select current_setting('{TENANT_SETTING}', true)")).scalar() == \
                "11111111-1111-1111-1111-111111111111"
        session.commit()
        # A second transaction with no scope carries the platform wildcard, not
        # the previous tenant: set_config(..., true) dies with its transaction.
        with platform_scope():
            assert session.execute(
                text(f"select current_setting('{TENANT_SETTING}', true)")).scalar() == PLATFORM_WILDCARD
        session.commit()


def test_enforcement_sees_the_policies_and_its_own_blind_spot(postgres_engine):
    with postgres_engine.connect() as connection:
        report = enforcement(connection)
    assert report["supported"] is True
    assert report["tenant_tables"] > 100, report
    # every tenant table is forced, or the owner would be exempt
    assert report["tables_with_rls_forced"] == report["tenant_tables"]
    assert report["policies"] >= report["tenant_tables"]
    # the app connects as a superuser here, and the report must say that instead
    # of claiming enforcement -- this is the honest half of the row
    if report["superuser"] or report["bypassrls"]:
        assert report["binds_this_role"] is False, (
            "a superuser is never bound by a policy; reporting True would be a lie")
