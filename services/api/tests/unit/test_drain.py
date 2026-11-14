"""LB drain: a retiring replica flips readiness to 503 while in-flight
requests finish — a rolling restart is a drain, never a reset."""

from __future__ import annotations

import pytest

from api import drain
from api.routers import health


@pytest.fixture(autouse=True)
def clean_drain():
    drain.reset()
    yield
    drain.reset()


class TestDrainState:

    def test_begin_drain_is_idempotent_and_first_reason_wins(self):
        assert drain.is_draining() is False
        drain.begin_drain("rolling_restart")
        drain.begin_drain("something_else")
        body = drain.as_dict()
        assert body["draining"] is True
        assert body["reason"] == "rolling_restart"
        assert isinstance(body["at"], float)

    def test_readyz_drains_the_load_balancer(self):
        drain.begin_drain("process_shutdown")
        response = health.readyz()
        assert response.status_code == 503
        assert response.body  # JSONResponse
        import json
        payload = json.loads(bytes(response.body))
        assert payload["status"] == "draining"
        assert payload["reason"] == "process_shutdown"
        assert "in-flight requests are finishing" in payload["detail"]

    def test_liveness_stays_up_through_a_drain(self):
        """/healthz is liveness: the process CAN serve (it is finishing
        in-flight work). Killing it now is the reset the drain exists to
        prevent — the health.py contract, enforced."""
        drain.begin_drain("process_shutdown")
        assert health.healthz() == {"status": "ok"}

    def test_not_draining_by_default(self):
        assert drain.as_dict() == {"draining": False}
