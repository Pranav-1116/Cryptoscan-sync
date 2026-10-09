"""A scan must not be reported accepted when its durable job write fails."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from api.routers import trigger


class BrokenSession:
    def __init__(self):
        self.rollback_calls = 0

    def commit(self):
        raise RuntimeError("database unavailable")

    def rollback(self):
        self.rollback_calls += 1


class BrokenJobRepo:
    def __init__(self):
        self.session = BrokenSession()
        self.created = None

    def create(self, **kwargs):
        self.created = kwargs
        return MagicMock(id="job-not-committed", status="QUEUED", created_at=None)


def test_enqueue_scan_job_fails_closed_when_job_commit_fails(monkeypatch):
    # Pin the admission DB seams (the module docstring's contract) so this
    # test exercises the job-commit failure path, not whatever SessionLocal
    # happens to be bound by whichever test ran before it in this worker.
    from api.security import scan_admission

    monkeypatch.setattr(scan_admission, "_control_plane_state", lambda: ([], None))
    monkeypatch.setattr(scan_admission, "_ot_declared", lambda: False)
    repo = BrokenJobRepo()
    monkeypatch.setattr(trigger, "_resolve_sector", lambda _sector, _repo: "generic")

    with pytest.raises(HTTPException) as error:
        trigger.enqueue_scan_job(
            repo,
            MagicMock(),
            repo_url="local://test-fixture/vulnerable-app",
            triggered_by="scanner-user",
        )

    assert error.value.status_code == 503
    assert "no job was accepted" in str(error.value.detail)
    assert repo.session.rollback_calls == 1
