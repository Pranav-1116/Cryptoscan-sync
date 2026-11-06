"""CI restore drills seed actual rows without touching a customer database."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[3]


def _script():
    spec = importlib.util.spec_from_file_location("restore_drill_seed", ROOT / "scripts" / "restore_drill_seed.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_seed_is_real_disabled_rows_not_a_success_only_receipt():
    from db.models.base import Base
    from db.models.tenant import Tenant
    from db.models.user import User

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Tenant.__table__, User.__table__])
    try:
        _script().seed(engine)
        with Session(engine) as session:
            assert session.scalars(select(Tenant.slug)).all() == ["restore-drill-ci-only"]
            user = session.scalar(select(User))
            assert user.username == "restore_drill_ci_only"
            assert user.is_active is False
            assert user.password_hash == "INVALID_TEST_ONLY_NEVER_AUTHENTICATES"
        with pytest.raises(RuntimeError, match="already seeded"):
            _script().seed(engine)
    finally:
        engine.dispose()


def test_cli_refuses_unmarked_or_non_disposable_databases(monkeypatch):
    script = _script()
    monkeypatch.delenv("CRYPTOSCAN_CI_DISPOSABLE_DB", raising=False)
    with pytest.raises(RuntimeError, match="explicitly disposable"):
        script.main()
    monkeypatch.setenv("CRYPTOSCAN_CI_DISPOSABLE_DB", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql://drill@bank.internal:5432/cryptoscan")
    monkeypatch.setenv("CRYPTOSCAN_RESTORE_TARGET_DB", "postgresql://drill@bank.internal:5432/restore_drill")
    with pytest.raises(RuntimeError, match="localhost restore-drill CI service"):
        script.main()
