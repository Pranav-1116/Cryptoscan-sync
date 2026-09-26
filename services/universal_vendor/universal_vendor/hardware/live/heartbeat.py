"""Hardware agent heartbeats (§4).

Every ZELNX edge agent reports: last heartbeat, last successful discovery,
last crypto check, last firmware check, event queue depth, event lag and
agent health. The central state engine consumes them.

**HEARTBEAT LOST → AGENT_UNAVAILABLE → ALERT**

Crucially, an agent going silent NEVER implies its hardware disappeared:
no HARDWARE_REMOVED event is ever synthesized from a missing heartbeat.
Hardware removal requires explicit discovery/management evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class AgentHealth(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    EVENT_DELAYED = "EVENT_DELAYED"
    FAILED = "FAILED"


class AgentStatus(str, Enum):
    ONLINE = "ONLINE"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


@dataclass
class HeartbeatRecord:
    agent_id: str
    last_heartbeat: str
    last_successful_discovery: Optional[str] = None
    last_crypto_check: Optional[str] = None
    last_firmware_check: Optional[str] = None
    event_queue_depth: int = 0
    event_lag_seconds: int = 0
    agent_health: str = AgentHealth.HEALTHY.value
    hardware_count: Optional[int] = None
    version: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "last_heartbeat": self.last_heartbeat,
            "last_successful_discovery": self.last_successful_discovery,
            "last_crypto_check": self.last_crypto_check,
            "last_firmware_check": self.last_firmware_check,
            "event_queue_depth": self.event_queue_depth,
            "event_lag_seconds": self.event_lag_seconds,
            "agent_health": self.agent_health,
            "hardware_count": self.hardware_count,
            "version": self.version,
        }


class AgentHeartbeatEngine:
    """Central heartbeat ingestion + health evaluation (§4)."""

    def __init__(
        self,
        *,
        stale_after_seconds: int = 300,
        unavailable_after_seconds: int = 900,
        max_event_lag_seconds: int = 60,
    ) -> None:
        self._records: dict[str, HeartbeatRecord] = {}
        self._alerts: list[dict[str, Any]] = []
        self._stale_after = stale_after_seconds
        self._unavailable_after = unavailable_after_seconds
        self._max_lag = max_event_lag_seconds

    # ── ingestion ─────────────────────────────────────────────────────

    def heartbeat(
        self,
        agent_id: str,
        *,
        last_successful_discovery: Optional[str] = None,
        last_crypto_check: Optional[str] = None,
        last_firmware_check: Optional[str] = None,
        event_queue_depth: int = 0,
        event_lag_seconds: int = 0,
        agent_health: str = AgentHealth.HEALTHY.value,
        hardware_count: Optional[int] = None,
        version: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> HeartbeatRecord:
        record = HeartbeatRecord(
            agent_id=agent_id,
            last_heartbeat=timestamp or _now(),
            last_successful_discovery=last_successful_discovery,
            last_crypto_check=last_crypto_check,
            last_firmware_check=last_firmware_check,
            event_queue_depth=max(0, int(event_queue_depth or 0)),
            event_lag_seconds=max(0, int(event_lag_seconds or 0)),
            agent_health=str(agent_health or AgentHealth.HEALTHY.value).upper(),
            hardware_count=hardware_count,
            version=version,
        )
        previous = self._records.get(agent_id)
        self._records[agent_id] = record

        # health state transitions produce alerts, never hardware events
        if previous is not None and previous.agent_health != record.agent_health:
            self._alerts.append({
                "alert_type": "AGENT_HEALTH_CHANGED",
                "agent_id": agent_id,
                "previous": previous.agent_health,
                "current": record.agent_health,
                "timestamp": record.last_heartbeat,
                "detail": f"agent {agent_id} health {previous.agent_health} -> "
                          f"{record.agent_health}",
            })
        if record.event_lag_seconds > self._max_lag:
            self._alerts.append({
                "alert_type": "EVENT_LAG",
                "agent_id": agent_id,
                "event_lag_seconds": record.event_lag_seconds,
                "timestamp": record.last_heartbeat,
                "detail": f"agent {agent_id} event lag "
                          f"{record.event_lag_seconds}s exceeds {self._max_lag}s",
            })
        return record

    # ── evaluation ────────────────────────────────────────────────────

    def agent_status(self, agent_id: str, *, now: Optional[str] = None) -> str:
        """ONLINE / STALE / UNAVAILABLE from the last heartbeat age."""
        record = self._records.get(agent_id)
        if record is None:
            return AgentStatus.UNAVAILABLE.value
        last = _parse(record.last_heartbeat)
        if last is None:
            return AgentStatus.UNAVAILABLE.value
        now_dt = _parse(now) or datetime.now(timezone.utc)
        age = (now_dt - last).total_seconds()
        if age > self._unavailable_after:
            return AgentStatus.UNAVAILABLE.value
        if age > self._stale_after:
            return AgentStatus.STALE.value
        return AgentStatus.ONLINE.value

    def evaluate(self, *, now: Optional[str] = None) -> list[dict[str, Any]]:
        """HEARTBEAT LOST → AGENT_UNAVAILABLE → ALERT for every stale agent.

        Returns alert dicts. Never emits HARDWARE_REMOVED — see module
        docstring (§4 hard rule).
        """
        now_dt = _parse(now) or datetime.now(timezone.utc)
        alerts: list[dict[str, Any]] = []
        for agent_id, record in self._records.items():
            status = self.agent_status(agent_id, now=now_dt.isoformat())
            if status == AgentStatus.UNAVAILABLE.value:
                alert = {
                    "alert_type": "AGENT_UNAVAILABLE",
                    "agent_id": agent_id,
                    "timestamp": now_dt.isoformat(),
                    "detail": (
                        f"heartbeat lost for agent {agent_id} — hardware behind the "
                        f"agent is NOT assumed removed; re-discovery required"
                    ),
                    "hardware_status_hint": "UNKNOWN",  # never REMOVED
                }
                self._alerts.append(alert)
                alerts.append(alert)
            elif status == AgentStatus.STALE.value:
                alert = {
                    "alert_type": "HEARTBEAT_LOST",
                    "agent_id": agent_id,
                    "timestamp": now_dt.isoformat(),
                    "detail": f"no heartbeat from agent {agent_id} within "
                              f"{self._stale_after}s",
                }
                self._alerts.append(alert)
                alerts.append(alert)
        return alerts

    def health(self, agent_id: str, *, now: Optional[str] = None) -> dict[str, Any]:
        """§4 metrics for one agent: LAST_HEARTBEAT, LAST_SUCCESSFUL_DISCOVERY,
        LAST_CRYPTO_CHECK, LAST_FIRMWARE_CHECK, EVENT_QUEUE, EVENT_LAG,
        AGENT_HEALTH + derived AGENT_STATUS."""
        record = self._records.get(agent_id)
        if record is None:
            return {"agent_id": agent_id, "agent_status": AgentStatus.UNAVAILABLE.value,
                    "known": False}
        return {
            "agent_id": agent_id,
            "known": True,
            "agent_status": self.agent_status(agent_id, now=now),
            "last_heartbeat": record.last_heartbeat,
            "last_successful_discovery": record.last_successful_discovery,
            "last_crypto_check": record.last_crypto_check,
            "last_firmware_check": record.last_firmware_check,
            "event_queue": record.event_queue_depth,
            "event_lag": record.event_lag_seconds,
            "agent_health": record.agent_health,
            "hardware_count": record.hardware_count,
        }

    def agents(self) -> list[dict[str, Any]]:
        return [self.health(a) for a in sorted(self._records)]

    def alerts(self) -> list[dict[str, Any]]:
        return list(self._alerts)

    def count(self) -> int:
        return len(self._records)

    def agent_hardware_known(self, agent_id: str) -> bool:
        """Whether we can trust inventory behind this agent right now."""
        return self.agent_status(agent_id) in (AgentStatus.ONLINE.value,
                                               AgentStatus.STALE.value)
