"""Deterministic operational health monitoring (no AI/ML).

Covers three surfaces with fixed-threshold, rule-based classification:

* **Connectors** (AWS/Azure/GCP/network/vendor/HSM): connected vs auth-failure vs
  stale — a failed/error connector raises an operational alert (section 23).
* **Agent fleet**: offline (no heartbeat past threshold), outdated (version below
  the target/expected), or unhealthy (reported flag). Offline agents alert;
  outdated agents are flagged for a signed, controlled update (section 22).
* **Self-monitoring**: platform components (API, workers, queue, event pipeline,
  database, scanners) are classified from posted metrics against fixed SLO
  thresholds — latency, queue depth, error rate, scanner failures (section 24).

Every decision is a comparison against explicit thresholds — same inputs always
yield the same health state, and each carries a human-readable reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable


class HealthState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


# agent heartbeat thresholds (seconds)
AGENT_STALE_SECONDS = 60        # heartbeat older than this -> degraded
AGENT_OFFLINE_SECONDS = 180     # older than this -> offline/critical
# connector staleness
CONNECTOR_STALE_HOURS = 24

_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def _now(now: datetime | None) -> datetime:
    n = now or datetime.now(timezone.utc)
    return n if n.tzinfo else n.replace(tzinfo=timezone.utc)


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def semver_tuple(version: str | None) -> tuple[int, int, int] | None:
    if not version:
        return None
    m = _SEMVER_RE.match(str(version).strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


@dataclass
class HealthAssessment:
    target_id: str
    kind: str            # connector | agent | component
    state: HealthState
    severity: Severity
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def alert(self) -> bool:
        return self.state in (HealthState.UNHEALTHY, HealthState.OFFLINE)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id, "kind": self.kind,
            "state": self.state.value, "severity": self.severity.value,
            "alert": self.alert, "reasons": self.reasons, "details": self.details,
        }


# ----------------------------------------------------------------- connectors
def assess_connector(conn: dict[str, Any], *, now: datetime | None = None) -> HealthAssessment:
    """Classify a cloud/network/vendor/HSM connector from status + test + heartbeat."""
    now = _now(now)
    cid = str(conn.get("id") or conn.get("name") or conn.get("kind") or "?")
    status = str(conn.get("status") or "").lower()
    link = str(conn.get("agent_link") or conn.get("link") or "").lower()
    reasons: list[str] = []
    details: dict[str, Any] = {"status": status, "kind": conn.get("kind")}

    test_result = conn.get("test_result") or {}
    auth_failed = bool(test_result.get("auth_error") or test_result.get("authentication_failure"))

    last_seen = _parse_dt(conn.get("agent_last_seen_at") or conn.get("last_tested_at"))
    if last_seen is not None:
        age_hours = (now - last_seen).total_seconds() / 3600.0
        details["last_seen_age_hours"] = round(age_hours, 2)
    else:
        age_hours = None

    if status == "error" or auth_failed:
        reason = "connector reported an error"
        if auth_failed:
            reason = "authentication failure (credential/permission issue)"
        return HealthAssessment(cid, "connector", HealthState.UNHEALTHY,
                                Severity.CRITICAL, [reason], details)
    if status == "connected" and link in ("encrypted", "connected") and conn.get("agent_healthy", True):
        # stale connected connector (no successful test in a day) -> degraded
        if age_hours is not None and age_hours > CONNECTOR_STALE_HOURS:
            reasons.append(f"connected but no successful test in {int(age_hours)}h")
            return HealthAssessment(cid, "connector", HealthState.DEGRADED,
                                    Severity.WARNING, reasons, details)
        return HealthAssessment(cid, "connector", HealthState.HEALTHY, Severity.INFO,
                                ["connector connected and healthy"], details)
    if status in ("pending", "configured", "planned"):
        reasons.append(f"connector not yet connected (status={status or 'pending'})")
        return HealthAssessment(cid, "connector", HealthState.DEGRADED, Severity.WARNING,
                                reasons, details)
    if status == "disconnected" or link == "disconnected":
        reasons.append("connector disconnected")
        return HealthAssessment(cid, "connector", HealthState.OFFLINE, Severity.CRITICAL,
                                reasons, details)
    return HealthAssessment(cid, "connector", HealthState.UNKNOWN, Severity.WARNING,
                            ["connector state could not be determined"], details)


# ----------------------------------------------------------------- agents
def assess_agent(agent: dict[str, Any], *, now: datetime | None = None,
                 expected_version: str | None = None) -> HealthAssessment:
    """Classify an agent: offline (stale heartbeat), outdated, or unhealthy."""
    now = _now(now)
    aid = str(agent.get("id") or agent.get("name") or "?")
    status = str(agent.get("status") or "").lower()
    link = str(agent.get("link") or "").lower()
    version = agent.get("version")
    target = expected_version or agent.get("target_version")
    reasons: list[str] = []
    details: dict[str, Any] = {"version": version, "target_version": target}

    heartbeat = _parse_dt(agent.get("last_heartbeat_at"))
    if heartbeat is not None:
        age = (now - heartbeat).total_seconds()
        details["heartbeat_age_seconds"] = int(age)
    else:
        age = None

    # offline: explicitly stopped, or heartbeat past the offline threshold
    if status in ("offline", "decommissioned", "revoked") or (
            age is not None and age > AGENT_OFFLINE_SECONDS) or (
            age is None and link == "disconnected" and not agent.get("healthy")):
        if age is not None and age > AGENT_OFFLINE_SECONDS:
            reasons.append(f"no heartbeat for {int(age)}s (>{AGENT_OFFLINE_SECONDS}s)")
        else:
            reasons.append(f"agent status={status or 'disconnected'}")
        return HealthAssessment(aid, "agent", HealthState.OFFLINE, Severity.CRITICAL,
                                reasons, details)

    # outdated: current version below target (deterministic semver)
    cur_v, tgt_v = semver_tuple(str(version)) if version else None, semver_tuple(str(target)) if target else None
    if cur_v and tgt_v and cur_v < tgt_v:
        reasons.append(f"agent version {version} below target {target} — schedule signed update")
        details["outdated"] = True
        # outdated but still heartbeating -> degraded (warning), not offline
        return HealthAssessment(aid, "agent", HealthState.DEGRADED, Severity.WARNING,
                                reasons, details)

    # unhealthy flag or stale-but-not-offline heartbeat
    if agent.get("healthy") is False:
        reasons.append("agent reported unhealthy")
        return HealthAssessment(aid, "agent", HealthState.UNHEALTHY, Severity.CRITICAL,
                                reasons, details)
    if age is not None and age > AGENT_STALE_SECONDS:
        reasons.append(f"heartbeat stale ({int(age)}s)")
        return HealthAssessment(aid, "agent", HealthState.DEGRADED, Severity.WARNING,
                                reasons, details)

    return HealthAssessment(aid, "agent", HealthState.HEALTHY, Severity.INFO,
                            ["agent online and current"], details)


# ----------------------------------------------------------------- self-monitoring
#: fixed SLO thresholds per platform metric: (warn_at, critical_at, comparator)
#: comparator "above" triggers when value >= threshold; "below" when <=.
METRIC_THRESHOLDS: dict[str, tuple[float, float, str, str]] = {
    # metric: (warn, critical, direction, unit)
    "api_latency_p95_ms": (500.0, 1000.0, "above", "ms"),
    "worker_latency_ms": (1000.0, 3000.0, "above", "ms"),
    "queue_depth": (100.0, 500.0, "above", "jobs"),
    "event_delay_seconds": (30.0, 120.0, "above", "s"),
    "error_rate_pct": (1.0, 5.0, "above", "%"),
    "scanner_failure_rate_pct": (5.0, 15.0, "above", "%"),
    "cpu_pct": (80.0, 95.0, "above", "%"),
    "memory_pct": (80.0, 95.0, "above", "%"),
    "storage_pct": (80.0, 92.0, "above", "%"),
    "success_rate_pct": (99.0, 95.0, "below", "%"),  # inverted: low success is bad
    "agents_online_pct": (90.0, 70.0, "below", "%"),
}


def assess_platform_metric(name: str, value: float) -> HealthAssessment:
    """Classify one platform metric against its fixed SLO threshold."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return HealthAssessment(name, "component", HealthState.UNKNOWN, Severity.WARNING,
                                [f"non-numeric metric value {value!r}"], {"value": value})
    spec = METRIC_THRESHOLDS.get(name)
    if spec is None:
        return HealthAssessment(name, "component", HealthState.UNKNOWN, Severity.INFO,
                                ["no threshold defined for metric"], {"value": v})
    warn, critical, direction, unit = spec
    if direction == "above":
        if v >= critical:
            state, sev = HealthState.UNHEALTHY, Severity.CRITICAL
        elif v >= warn:
            state, sev = HealthState.DEGRADED, Severity.WARNING
        else:
            state, sev = HealthState.HEALTHY, Severity.INFO
    else:  # below (e.g. success rate) — lower is worse, critical threshold is the floor
        if v <= critical:
            state, sev = HealthState.UNHEALTHY, Severity.CRITICAL
        elif v <= warn:
            state, sev = HealthState.DEGRADED, Severity.WARNING
        else:
            state, sev = HealthState.HEALTHY, Severity.INFO
    reasons = []
    if state != HealthState.HEALTHY:
        reasons.append(f"{name}={v}{unit} breached {direction}-threshold (warn {warn}, critical {critical})")
    return HealthAssessment(name, "component", state, sev, reasons,
                            {"value": v, "unit": unit, "warn_at": warn, "critical_at": critical})


# ----------------------------------------------------------------- batch watch
@dataclass
class HealthReport:
    targets: list[HealthAssessment] = field(default_factory=list)

    @property
    def alerts(self) -> list[HealthAssessment]:
        return [t for t in self.targets if t.alert]

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    def as_dict(self) -> dict[str, Any]:
        states = {}
        for t in self.targets:
            states[t.state.value] = states.get(t.state.value, 0) + 1
        return {
            "total": len(self.targets),
            "states": states,
            "alert_count": len(self.alerts),
            "targets": [t.as_dict() for t in self.targets],
            "alerts": [t.as_dict() for t in self.alerts],
        }


def watch_connectors(connectors: Iterable[dict[str, Any]], *, now: datetime | None = None) -> HealthReport:
    return HealthReport(targets=[assess_connector(c, now=now) for c in connectors])


def watch_agents(agents: Iterable[dict[str, Any]], *, now: datetime | None = None,
                 expected_version: str | None = None) -> HealthReport:
    return HealthReport(targets=[assess_agent(a, now=now, expected_version=expected_version) for a in agents])


def watch_platform(metrics: dict[str, float]) -> HealthReport:
    return HealthReport(targets=[assess_platform_metric(k, v) for k, v in metrics.items()])
