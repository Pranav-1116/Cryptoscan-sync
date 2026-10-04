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
