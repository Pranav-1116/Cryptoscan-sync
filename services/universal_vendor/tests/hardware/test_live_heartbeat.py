"""Agent heartbeats — ingestion, health, HEARTBEAT LOST → AGENT_UNAVAILABLE
(§4). The golden rule: a missing agent NEVER removes its hardware."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from universal_vendor.hardware.live import (
    AgentHeartbeatEngine,
    AgentStatus,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ago(seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


def test_heartbeat_ingestion_metrics():
    engine = AgentHeartbeatEngine()
    engine.heartbeat(
        "edge-1",
        last_successful_discovery=_now(),
        last_crypto_check=_now(),
        last_firmware_check=_now(),
        event_queue_depth=3,
        event_lag_seconds=5,
        agent_health="HEALTHY",
        hardware_count=42,
    )
    health = engine.health("edge-1")
    assert health["agent_status"] == "ONLINE"
    assert health["event_queue"] == 3
    assert health["event_lag"] == 5
    assert health["agent_health"] == "HEALTHY"
    assert health["hardware_count"] == 42
    assert health["last_successful_discovery"] is not None


def test_unknown_agent_is_unavailable():
    engine = AgentHeartbeatEngine()
    assert engine.health("ghost")["agent_status"] == "UNAVAILABLE"
    assert engine.health("ghost")["known"] is False


def test_heartbeat_lost_then_agent_unavailable():
    engine = AgentHeartbeatEngine(stale_after_seconds=60, unavailable_after_seconds=300)
    engine.heartbeat("edge-2", timestamp=_ago(500))
    alerts = engine.evaluate(now=_now())
    types = {a["alert_type"] for a in alerts}
    assert "AGENT_UNAVAILABLE" in types
    detail = next(a for a in alerts if a["alert_type"] == "AGENT_UNAVAILABLE")
    assert "NOT assumed removed" in detail["detail"]
    assert detail["hardware_status_hint"] == "UNKNOWN"


def test_stale_but_not_unavailable():
    engine = AgentHeartbeatEngine(stale_after_seconds=60, unavailable_after_seconds=300)
    engine.heartbeat("edge-3", timestamp=_ago(120))
    alerts = engine.evaluate(now=_now())
    assert {a["alert_type"] for a in alerts} == {"HEARTBEAT_LOST"}
    assert engine.agent_status("edge-3") == AgentStatus.STALE.value


def test_missing_heartbeat_never_removes_hardware():
    """§4 hard rule: AGENT_UNAVAILABLE must not synthesize HARDWARE_REMOVED."""
    engine = AgentHeartbeatEngine(stale_after_seconds=1, unavailable_after_seconds=5)
    engine.heartbeat("edge-4", timestamp=_ago(600))
    alerts = engine.evaluate(now=_now())
    assert alerts, "expected an availability alert"
    for alert in alerts:
        assert alert["alert_type"] != "HARDWARE_REMOVED"
        assert "HARDWARE_REMOVED" not in alert["detail"]


def test_health_change_alert():
    engine = AgentHeartbeatEngine()
    engine.heartbeat("edge-5", agent_health="HEALTHY")
    engine.heartbeat("edge-5", agent_health="DEGRADED")
    kinds = {a["alert_type"] for a in engine.alerts()}
    assert "AGENT_HEALTH_CHANGED" in kinds


def test_event_lag_alert():
    engine = AgentHeartbeatEngine(max_event_lag_seconds=60)
    engine.heartbeat("edge-6", event_lag_seconds=600)
    assert any(a["alert_type"] == "EVENT_LAG" for a in engine.alerts())


def test_agent_hardware_known_guard():
    engine = AgentHeartbeatEngine(stale_after_seconds=60, unavailable_after_seconds=300)
    engine.heartbeat("edge-7")
    assert engine.agent_hardware_known("edge-7") is True
    engine.heartbeat("edge-7", timestamp=_ago(400))
    assert engine.agent_hardware_known("edge-7") is False
