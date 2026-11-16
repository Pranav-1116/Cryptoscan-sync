"""Suspicious-access detection — the pattern between the rate limiter
and the audit chain.

Pinned here: the threshold flags, the window expires (stale suspicion is
never reported as current), success does NOT erase history (a valid
guess after a hundred wrong ones must stay visible), the monitor is
bounded (it can never become a second outage), and the surface reports
observations only.
"""
from __future__ import annotations

import pytest

from api.security import auth_monitor


@pytest.fixture(autouse=True)
def _fresh_window():
    """The window is process state — isolate every test (class methods
    included: ``setup_function`` does not run for those) from buckets left
    by other suites that exercise real logins."""
    auth_monitor.reset()
    yield
    auth_monitor.reset()


class TestTheWindow:
    def test_threshold_flags_the_key(self):
        now = 1_000_000.0
        for i in range(auth_monitor.THRESHOLD - 1):
            state = auth_monitor.record_failure("alice", "10.0.0.9", now=now + i)
            assert state["suspicious"] is False
        state = auth_monitor.record_failure("alice", "10.0.0.9",
                                            now=now + auth_monitor.THRESHOLD)
        assert state["suspicious"] is True

    def test_the_window_expires_stale_suspicion(self):
        now = 2_000_000.0
        for i in range(auth_monitor.THRESHOLD):
            auth_monitor.record_failure("bob", "10.0.0.7", now=now + i)
        assert auth_monitor.suspicious(now=now + 1)["suspicious"] is True
        after = now + auth_monitor.WINDOW_SECONDS + 10
        state = auth_monitor.suspicious(now=after)
        assert state["suspicious"] is False
        assert state["total_failures_in_window"] == 0

    def test_success_never_erases_history(self):
        now = 3_000_000.0
        for i in range(auth_monitor.THRESHOLD):
            auth_monitor.record_failure("carol", "10.0.0.5", now=now + i)
        # one success does not forgive the probe pattern — only time does
        state = auth_monitor.suspicious(now=now + 1)
        assert state["suspicious"] is True
        assert state["suspicious_keys"][0]["user"] == "carol"

    def test_keys_and_buckets_stay_bounded(self):
        now = 4_000_000.0
        for i in range(auth_monitor.MAX_PER_KEY + 25):
            auth_monitor.record_failure("dave", "10.0.0.3", now=now)
        for i in range(auth_monitor.MAX_KEYS + 25):
            auth_monitor.record_failure(f"user{i}", "10.0.0.4", now=now)
        from api.security.auth_monitor import _FAILURES

        with auth_monitor._LOCK:
            assert len(_FAILURES) <= auth_monitor.MAX_KEYS
            for bucket in _FAILURES.values():
                assert len(bucket) <= auth_monitor.MAX_PER_KEY

    def test_unflagged_keys_are_observations_not_noise(self):
        now = 5_000_000.0
        auth_monitor.record_failure("eve", "10.0.0.2", now=now)
        state = auth_monitor.suspicious(now=now + 1)
        assert state["suspicious"] is False
        assert state["total_failures_in_window"] == 1
        assert state["suspicious_keys"] == []


class TestTheSurface:
    def test_metrics_report_the_window_and_flags(self):
        import time as _time

        import api.routers.metrics as metrics_mod

        now = _time.time()
        for i in range(auth_monitor.THRESHOLD):
            auth_monitor.record_failure("mallory", "10.0.0.6", now=now - 1)
        rendered = "".join(metrics_mod._auth_lines())
        assert f"cryptoscan_auth_failures_in_window {auth_monitor.THRESHOLD}" in rendered
        assert "cryptoscan_auth_suspicious_keys 1" in rendered

    def test_metrics_degrade_never_die(self, monkeypatch):
        import api.routers.metrics as metrics_mod

        def boom():
            raise RuntimeError("monitor down")

        monkeypatch.setattr("api.security.auth_monitor.suspicious", boom)
        assert metrics_mod._auth_lines() == []
