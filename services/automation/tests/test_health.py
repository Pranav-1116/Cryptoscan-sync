"""Deterministic operational health monitoring tests (no AI/ML)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from automation.health import (
    HealthState,
    Severity,
    assess_agent,
    assess_connector,
    assess_platform_metric,
    watch_agents,
    watch_connectors,
    watch_platform,
)

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)


# ----------------------------------------------------------------- connectors
class TestConnectorHealth:
    def test_connected_encrypted_healthy(self):
        a = assess_connector({"id": "aws", "status": "connected",
                              "agent_link": "encrypted", "agent_healthy": True}, now=NOW)
        assert a.state == HealthState.HEALTHY

    def test_auth_failure_unhealthy_critical(self):
        a = assess_connector({"id": "hsm", "status": "error",
                              "test_result": {"authentication_failure": True}}, now=NOW)
        assert a.state == HealthState.UNHEALTHY and a.severity == Severity.CRITICAL
        assert a.alert

    def test_disconnected_offline(self):
        a = assess_connector({"id": "cisco", "status": "disconnected",
                              "agent_link": "disconnected"}, now=NOW)
        assert a.state == HealthState.OFFLINE

    def test_stale_connected_degraded(self):
        a = assess_connector({"id": "aws", "status": "connected", "agent_link": "encrypted",
                              "agent_healthy": True,
                              "last_tested_at": (NOW - timedelta(hours=48)).isoformat()}, now=NOW)
        assert a.state == HealthState.DEGRADED

    def test_pending_degraded(self):
        a = assess_connector({"id": "gcp", "status": "pending"}, now=NOW)
        assert a.state == HealthState.DEGRADED


# ----------------------------------------------------------------- agents
class TestAgentHealth:
    def test_fresh_agent_healthy(self):
        a = assess_agent({"id": "a1", "version": "2.1.0", "healthy": True,
                          "last_heartbeat_at": (NOW - timedelta(seconds=10)).isoformat()},
                         now=NOW, expected_version="2.1.0")
        assert a.state == HealthState.HEALTHY

    def test_no_heartbeat_offline(self):
        a = assess_agent({"id": "a2", "version": "2.1.0", "healthy": True,
                          "last_heartbeat_at": (NOW - timedelta(seconds=400)).isoformat()}, now=NOW)
        assert a.state == HealthState.OFFLINE and a.severity == Severity.CRITICAL

    def test_stale_heartbeat_degraded(self):
        a = assess_agent({"id": "a3", "version": "2.1.0", "healthy": True,
                          "last_heartbeat_at": (NOW - timedelta(seconds=90)).isoformat()}, now=NOW)
        assert a.state == HealthState.DEGRADED

    def test_outdated_version_degraded(self):
        a = assess_agent({"id": "a4", "version": "1.9.0", "healthy": True,
                          "last_heartbeat_at": (NOW - timedelta(seconds=5)).isoformat()},
                         now=NOW, expected_version="2.0.0")
        assert a.state == HealthState.DEGRADED
        assert a.details.get("outdated") is True

    def test_reports_unhealthy(self):
        a = assess_agent({"id": "a5", "version": "2.0.0", "healthy": False,
                          "last_heartbeat_at": (NOW - timedelta(seconds=5)).isoformat()},
                         now=NOW, expected_version="2.0.0")
        assert a.state == HealthState.UNHEALTHY

    def test_semver_compare(self):
        # target 2.0.0 vs current 1.10.0 -> 1 < 2 so outdated
        a = assess_agent({"id": "a6", "version": "1.10.0", "healthy": True,
                          "last_heartbeat_at": (NOW - timedelta(seconds=5)).isoformat()},
                         now=NOW, expected_version="2.0.0")
        assert a.state == HealthState.DEGRADED


# ----------------------------------------------------------------- platform metrics
class TestPlatformMetrics:
    def test_latency_healthy_warn_critical(self):
        assert assess_platform_metric("api_latency_p95_ms", 120).state == HealthState.HEALTHY
        assert assess_platform_metric("api_latency_p95_ms", 700).state == HealthState.DEGRADED
        assert assess_platform_metric("api_latency_p95_ms", 1500).state == HealthState.UNHEALTHY

    def test_queue_depth(self):
        assert assess_platform_metric("queue_depth", 20).state == HealthState.HEALTHY
        assert assess_platform_metric("queue_depth", 600).state == HealthState.UNHEALTHY

    def test_success_rate_inverted(self):
        # lower success is worse
        assert assess_platform_metric("success_rate_pct", 99.9).state == HealthState.HEALTHY
        assert assess_platform_metric("success_rate_pct", 97.0).state == HealthState.DEGRADED
        assert assess_platform_metric("success_rate_pct", 90.0).state == HealthState.UNHEALTHY

    def test_unknown_metric(self):
        assert assess_platform_metric("made_up_metric", 1).state == HealthState.UNKNOWN

    def test_watch_platform_report(self):
        report = watch_platform({"queue_depth": 600, "cpu_pct": 30})
        assert report.alert_count == 1
        assert report.as_dict()["states"].get("UNHEALTHY") == 1


def test_watch_connectors_and_agents_batch():
    conns = watch_connectors([
        {"id": "ok", "status": "connected", "agent_link": "encrypted"},
        {"id": "bad", "status": "error", "test_result": {"auth_error": True}},
    ], now=NOW)
    assert len(conns.alerts) == 1

    agents = watch_agents([
        {"id": "ok", "version": "2.0.0", "healthy": True,
         "last_heartbeat_at": (NOW - timedelta(seconds=5)).isoformat()},
        {"id": "dead", "version": "2.0.0",
         "last_heartbeat_at": (NOW - timedelta(seconds=999)).isoformat()},
    ], now=NOW, expected_version="2.0.0")
    assert len(agents.alerts) == 1 and agents.alerts[0].target_id == "dead"
