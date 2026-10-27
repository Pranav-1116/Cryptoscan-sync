"""Parser failure -> durable UNKNOWN, with real SQL and mocked daemon/runtime.

This is not Docker cleanup, PostgreSQL, escape or bank-site qualification.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from db.connection.session import SessionLocal
from db.models.execution_control import ExecutionAttempt, ExecutionBudget
from db.models.scan_job import ScanJob
from db.repositories import execution_control as controls
from worker.core import static_scan_isolation as isolation
from worker.core.job_executor import JobExecutor
from test_execution_controls import approve, configure, queue
from test_execution_controls import controlled as controlled
from test_software_supply_chain_api import banks as banks


@pytest.mark.parametrize("fault", ["launch", "invalid-result", "cleanup-unknown", "cancelled"])
def test_parser_failure_never_releases_reservations_or_reexecutes(controlled, monkeypatch, fault):
    configure(controlled)
    approve(controlled)
    row, descriptor = queue(controlled)
    job_id = row.id
    monkeypatch.setattr(isolation, "_configuration", lambda: SimpleNamespace(
        ENVIRONMENT="test", CRYPTOSCAN_STATIC_SCAN_MODE="container",
        CRYPTOSCAN_SCANNER_IMAGE="example.invalid/scanner@sha256:" + "a" * 64,
        CRYPTOSCAN_STATIC_SCAN_TIMEOUT_S=30))
    monkeypatch.setattr(isolation.shutil, "which", lambda name: "/usr/bin/docker")
    removed = []

    def cleanup(command, **kwargs):
        removed.append(command)
        if fault == "cleanup-unknown":
            return SimpleNamespace(returncode=1, stdout=b"still-present")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(isolation.subprocess, "run", cleanup)
    if fault == "launch":
        monkeypatch.setattr(isolation.subprocess, "Popen", Mock(side_effect=OSError("private-runtime-canary")))
    elif fault == "cancelled":
        monkeypatch.setattr(isolation, "_exchange", Mock(side_effect=asyncio.CancelledError("synthetic cancellation")))
    else:
        monkeypatch.setattr(isolation, "_exchange", lambda *args, **kwargs: b"invalid protocol result")
    executor = JobExecutor()
    calls = []

    def parser(**kwargs):
        calls.append(kwargs["job_id"])
        return isolation.scan_static(root_path=controlled["target"], scan_id="candidate-result")

    executor.runner.run = parser
    expected = asyncio.CancelledError if fault == "cancelled" else isolation.StaticScanIsolationError
    with pytest.raises(expected) as caught:
        executor.execute(descriptor)
    assert "private-runtime-canary" not in str(caught.value)
    assert controls.active_execution() is None
    assert removed[0][1:3] == ["rm", "--force"]
    assert list(controlled["tmp"].rglob(".cryptoscan-scan-*")) == []
    with SessionLocal() as db:
        job = db.get(ScanJob, job_id)
        attempt = db.query(ExecutionAttempt).filter_by(job_id=job_id).one()
        assert job.status == attempt.status == "UNKNOWN" and job.scan_id is None
        assert all(b.active == 1 for b in db.query(ExecutionBudget))
        versions = (job.version, attempt.version)
    assert not executor.execute(descriptor) and calls == [job_id]
    with SessionLocal() as db:
        job = db.get(ScanJob, job_id)
        attempt = db.query(ExecutionAttempt).filter_by(job_id=job_id).one()
        assert (job.version, attempt.version) == versions
        assert all(b.active == 1 for b in db.query(ExecutionBudget))
