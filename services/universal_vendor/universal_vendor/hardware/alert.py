"""Hardware alert correlation (§21).

Avoid alert storms: a server firmware update touching BIOS + BMC + TPM +
crypto capability generates ONE ROOT HARDWARE CHANGE with child events, not
four unrelated incidents.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

# child event types that collapse under a root hardware change
_CHILD_TYPES = ("BIOS_CHANGED", "BMC_CHANGED", "TPM_STATE_CHANGED",
                "TPM_CHANGED", "HSM_CHANGED", "HSM_CAPABILITY_CHANGED",
                "CRYPTO_SUPPORT_CHANGED", "CONFIGURATION_CHANGED",
                "CRYPTO_CAPABILITY_RE_EVALUATED", "CRYPTO_CAPABILITY_CHANGED",
                "NIC_CHANGED", "FIRMWARE_CHANGED")


class HardwareAlertCorrelator:
    def __init__(self) -> None:
        self._incidents: dict[str, dict[str, Any]] = {}
        self._child_events: dict[str, list[dict[str, Any]]] = {}

    def report(self, *, root_asset_id: str, root_type: str = "HARDWARE_CHANGE",
               event_type: str, detail: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Report one hardware event; child events collapse under the root."""
        now = datetime.now(timezone.utc).isoformat()
        is_child = event_type in _CHILD_TYPES
        root_key = f"{root_asset_id}:{root_type}"

        incident = self._incidents.setdefault(root_key, {
            "incident_id": root_key,
            "root_asset_id": root_asset_id,
            "root_type": root_type,
            "child_events": [],
            "first_seen": now,
            "last_seen": now,
        })
        incident["last_seen"] = now

        event = {"event_type": event_type, "detail": detail or {}, "timestamp": now}
        if is_child:
            self._child_events.setdefault(root_key, []).append(event)
            incident["child_events"] = self._child_events[root_key]
        else:
            incident["last_seen"] = now
            incident.setdefault("root_events", []).append(event)

        return incident

    def incidents(self) -> list[dict[str, Any]]:
        out = []
        for incident in self._incidents.values():
            out.append({
                "incident_id": incident["incident_id"],
                "root_asset_id": incident["root_asset_id"],
                "root_type": incident["root_type"],
                "root_event_count": len(incident.get("root_events", [])),
                "child_event_count": len(incident.get("child_events", [])),
                "child_types": sorted({e["event_type"] for e in incident.get("child_events", [])}),
                "first_seen": incident["first_seen"],
                "last_seen": incident["last_seen"],
                "summary": f"ONE ROOT {incident['root_type']} on "
                           f"{incident['root_asset_id']} with "
                           f"{len(incident.get('child_events', []))} child events",
            })
        return out

    def count(self) -> int:
        return len(self._incidents)
