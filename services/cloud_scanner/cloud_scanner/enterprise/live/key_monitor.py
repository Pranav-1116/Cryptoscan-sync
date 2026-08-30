"""ZELNX Live Cloud Intelligence Engine — live KMS / key monitoring (§8).

Monitors key lifecycle events and derives the universal blast-radius flow:

    KEY EVENT → IDENTIFY KEY → FIND ALL DEPENDENCIES → IDENTIFY
    APPLICATIONS → IDENTIFY DATASETS → IDENTIFY NETWORK SERVICES →
    UPDATE CRYPTO GRAPH → CALCULATE BLAST RADIUS

Monitored changes: key created / disabled / enabled / rotated / scheduled
for deletion / policy changed / permission changed / algorithm changed /
protection level changed.  **Never retrieves actual key material** — only
metadata, dependencies and access bindings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.live.event_schema import CloudEvent

KEY_EVENT_TYPES = (
    "KEY_CREATED", "KEY_DISABLED", "KEY_ENABLED", "KEY_ROTATED",
    "KEY_SCHEDULED_FOR_DELETION", "KEY_POLICY_CHANGED", "KEY_PERMISSION_CHANGED",
    "KEY_ALGORITHM_CHANGED", "KEY_PROTECTION_LEVEL_CHANGED",
)


def is_key_event(event_type: str) -> bool:
    # KEY_CHANGED is the universal generic key mutation event (§18)
    return str(event_type or "") in KEY_EVENT_TYPES or event_type == "KEY_CHANGED"


@dataclass
class KeyBlastRadius:
    """Impact of a key change on the surrounding estate."""

    key_id: str
    event_type: str = ""
    dependencies: list[str] = field(default_factory=list)
    applications: list[str] = field(default_factory=list)
    datasets: list[str] = field(default_factory=list)
    network_services: list[str] = field(default_factory=list)
    access_bindings: list[str] = field(default_factory=list)
    severity: str = "LOW"  # LOW | MEDIUM | HIGH | CRITICAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "event_type": self.event_type,
            "dependencies": list(self.dependencies),
            "applications": list(self.applications),
            "datasets": list(self.datasets),
            "network_services": list(self.network_services),
            "access_bindings": list(self.access_bindings),
            "severity": self.severity,
        }


class LiveKeyMonitor:
    """Watch key events and compute per-key blast radius.

    Dependencies are injected: ``find_dependencies(key_id)`` returns
    resource rows; ``find_access(key_id)`` returns identity rows.
    """

    def __init__(
        self,
        *,
        find_dependencies=None,
        find_access=None,
        severity_fn=None,
    ) -> None:
        self._find_dependencies = find_dependencies or (lambda key_id: [])
        self._find_access = find_access or (lambda key_id: [])
        self._severity = severity_fn or default_key_severity
        self._impacts: list[KeyBlastRadius] = []

    def watch(self, event: CloudEvent) -> KeyBlastRadius | None:
        if not is_key_event(event.event_type):
            return None
        deps = self._find_dependencies(event.resource_id)
        radius = KeyBlastRadius(
            key_id=event.resource_id,
            event_type=event.event_type,
            dependencies=[str(row.get("resource") if isinstance(row, dict) else row)
                          for row in deps],
            access_bindings=[str(row.get("identity") if isinstance(row, dict) else row)
                             for row in self._find_access(event.resource_id)],
        )
        for row in deps:
            kind = str(row.get("kind") or row.get("type") or "") if isinstance(row, dict) else ""
            target = str(row.get("resource") or row) if isinstance(row, dict) else str(row)
            if kind in ("application", "workload", "lambda", "function", "vm", "pod"):
                radius.applications.append(target)
            elif kind in ("dataset", "bucket", "database", "storage", "s3", "rds"):
                radius.datasets.append(target)
            elif kind in ("network", "lb", "elb", "api", "vpn", "endpoint"):
                radius.network_services.append(target)
        radius.severity = self._severity(event, radius)
        self._impacts.append(radius)
        return radius

    def impacts(self) -> list[KeyBlastRadius]:
        return list(self._impacts)

    def watchers_impacts(self) -> list[KeyBlastRadius]:
        return list(self._impacts)

    def summary(self) -> dict[str, Any]:
        return {
            "impacts": len(self._impacts),
            "by_severity": {
                severity: sum(1 for r in self._impacts if r.severity == severity)
                for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            },
        }


def default_key_severity(event: CloudEvent, radius: KeyBlastRadius) -> str:
    """Severity from event type + blast radius size."""
    if event.event_type in ("KEY_DISABLED", "KEY_SCHEDULED_FOR_DELETION",
                            "KEY_POLICY_CHANGED", "KEY_PERMISSION_CHANGED"):
        return "HIGH"
    if event.event_type == "KEY_ALGORITHM_CHANGED":
        return "HIGH"
    if len(radius.dependencies) >= 5:
        return "MEDIUM"
    if len(radius.dependencies) == 0 and event.event_type == "KEY_ROTATED":
        return "LOW"
    return "MEDIUM" if radius.dependencies else "LOW"
