"""A refused job must stay a refusal — even when the database is the reason.

The execution gate (round 46) fails closed when it cannot read the control
plane, and ``JobExecutor._gated`` then stamps the row FAILED so the refusal is
visible and the dead-letter threshold can count it. That stamp needs a session,
and on a cold process — a fresh worker boot, a test module that never ran
``init_db()``, or a database that is itself the outage — the stamp raised
instead:

    UnboundExecutionError: 'Session' object not connected to an Engine...

escaped ``execute()``, the pool logged ``job_execution_failed`` (a crash) and
the row was never stamped with the gate reason. The operator saw a worker
error, not a policy refusal, and the audit trail lost the one sentence that
explains why the scan did not run.
"""
from __future__ import annotations

from sqlalchemy.exc import UnboundExecutionError

from worker.core.job_consumer import ScanJob
from worker.core.job_executor import JobExecutor


class _Logger:
    """structlog-shaped recorder — the tests assert on the log line, not the sink."""

    def __init__(self) -> None:
        self.lines: list[tuple[str, dict]] = []

    def _record(self, event: str, *args, **kwargs) -> None:
        # the executor logs ``logger.warning(event, extra={...})``: flatten the
        # ``extra`` mapping so the assertions read the fields, not the envelope
        data = dict(kwargs.pop("extra", None) or {})
        data.update(kwargs)
        self.lines.append((event, data))

    info = warning = error = debug = _record

    def events(self) -> list[str]:
        return [event for event, _ in self.lines]


def _job() -> ScanJob:
    return ScanJob(job_id="j-refusal", target_repo="binary:///tmp/x", job_type="BINARY")


def _never_runs(**kwargs):
    raise AssertionError("a refused job must not be executed")


def test_refusal_stamps_the_row_failed_with_the_gate_reason(monkeypatch):
    """Happy path: the gate refuses, the reason reaches the job row."""
    stamped: list[tuple[str, str]] = []

    class _Session:
        def close(self) -> None:
            pass

    monkeypatch.setattr("worker.core.job_executor.gate_job",
                        lambda job, repository_target: (False, "repository target"))
    monkeypatch.setattr("db.connection.session.SessionLocal", lambda: _Session())
    monkeypatch.setattr("worker.core.job_reaper.fail_job",
                        lambda session, job_id, message: stamped.append((job_id, message)))

    executor = JobExecutor()
    assert executor._gated(_job(), repository_target=False, run=_never_runs) is False

    assert stamped == [("j-refusal", "execution gate: repository target")]


def test_refusal_stays_a_refusal_when_the_stamp_cannot_open_a_session(monkeypatch):
    """An unbound engine must not turn a policy refusal into a crash."""
    monkeypatch.setattr("worker.core.job_executor.gate_job",
                        lambda job, repository_target: (False, "unauthorized target"))

    def _boom():
        raise UnboundExecutionError(
            "'Session' object not connected to an Engine, and no bind engine "
            "was passed explicitly")

    monkeypatch.setattr("db.connection.session.SessionLocal", _boom)
    recorder = _Logger()
    monkeypatch.setattr("worker.core.job_executor.logger", recorder)

    executor = JobExecutor()
    result = executor.execute(_job())  # must return, not raise

    assert result is False
    # the refusal is still announced, and its cause is the gate's, not the DB's
    assert "job_refused_at_execution" in recorder.events()
    assert "job_refusal_stamp_failed" in recorder.events()
    line = dict(recorder.lines)["job_refusal_stamp_failed"]
    assert line["reason"].startswith("execution gate: unauthorized target")
    assert line["error_type"] == "UnboundExecutionError"


def test_refusal_stays_a_refusal_when_the_stamp_fails_mid_transaction(monkeypatch):
    """Same contract when the session opens but the write itself fails."""
    rolled_back: list[bool] = []
    closed: list[bool] = []

    class _Session:
        def rollback(self) -> None:
            rolled_back.append(True)

        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr("worker.core.job_executor.gate_job",
                        lambda job, repository_target: (False, "target outside platform scope"))
    monkeypatch.setattr("db.connection.session.SessionLocal", lambda: _Session())

    def _fail(*args, **kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr("worker.core.job_reaper.fail_job", _fail)
    recorder = _Logger()
    monkeypatch.setattr("worker.core.job_executor.logger", recorder)

    executor = JobExecutor()
    assert executor.execute(_job()) is False
    # the failed transaction is unwound and the connection is handed back
    assert rolled_back == [True]
    assert closed == [True]
    assert dict(recorder.lines)["job_refusal_stamp_failed"]["error_type"] == "RuntimeError"


def test_permitted_job_still_runs(monkeypatch):
    """The gate is a decision, not a dead end."""
    ran: list[str] = []
    monkeypatch.setattr("worker.core.job_executor.gate_job",
                        lambda job, repository_target: (True, None))
    executor = JobExecutor()

    result = executor._gated(_job(), repository_target=False,
                             run=lambda: ran.append("ok") or True)

    assert result is True and ran == ["ok"]
