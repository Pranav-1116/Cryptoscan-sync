"""Independent SQL sessions contend for the SAME budget (SQLite qualification only)."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from db.connection.session import Base
from db.models.execution_control import ExecutionBudget
from db.repositories.execution_control import _budget_change, ExecutionDenied


@pytest.mark.parametrize("operation", ["acquire", "request"])
def test_parallel_budget_cas_never_overbooks_one_slot_or_request(tmp_path, operation):
    engine = create_engine(f"sqlite:///{tmp_path}/shared-budget.db", connect_args={"timeout": 2})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions.begin() as session:
        session.add(ExecutionBudget(id="shared", capacity=1, requests_per_second=1))
    barrier = Barrier(8)
    def reserve(_):
        with sessions() as session:
            barrier.wait(timeout=5)
            try:
                _budget_change(session, "shared", **{operation: True})
                session.commit()
                return True
            except (ExecutionDenied, OperationalError):
                session.rollback()
                return False
    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(reserve, range(8))) == 1
    with sessions() as session:
        row = session.execute(select(ExecutionBudget)).scalar_one()
        assert row.active == (1 if operation == "acquire" else 0)
        assert len(row.request_times) == (1 if operation == "request" else 0)
    engine.dispose()


def test_fast_worker_clock_cannot_reset_shared_request_window(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from db.repositories import execution_control
    engine = create_engine(f"sqlite:///{tmp_path}/server-clock.db")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    with sessions.begin() as session:
        session.add(ExecutionBudget(id="shared", capacity=1, requests_per_second=1))
    with sessions.begin() as session:
        _budget_change(session, "shared", request=True)
    monkeypatch.setattr(execution_control, "utcnow", lambda: datetime(2099, 1, 1, tzinfo=timezone.utc))
    with sessions() as session, pytest.raises(ExecutionDenied, match="rolling request"):
        _budget_change(session, "shared", request=True)
    engine.dispose()
