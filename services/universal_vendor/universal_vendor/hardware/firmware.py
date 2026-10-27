"""Firmware intelligence (§9).

Monitor BIOS, UEFI, BMC, NIC, RAID, HBA, TPM, HSM, storage and network
appliance firmware. State: previous → current → firmware change →
capability reassessment. A firmware change triggers targeted cryptographic
re-evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from universal_vendor.hardware.models import FirmwareComponent, FirmwareState

MONITORED_COMPONENTS = [
    FirmwareComponent.BIOS, FirmwareComponent.UEFI, FirmwareComponent.BMC,
    FirmwareComponent.NIC, FirmwareComponent.RAID, FirmwareComponent.HBA,
    FirmwareComponent.TPM, FirmwareComponent.HSM, FirmwareComponent.STORAGE,
    FirmwareComponent.NETWORK_APPLIANCE, FirmwareComponent.GPU,
]


@dataclass
class FirmwareChange:
    asset_id: str
    component: str
    previous: str
    current: str
    timestamp: str
    reassessment_triggered: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "component": self.component,
                "previous": self.previous, "current": self.current,
                "timestamp": self.timestamp,
                "reassessment_triggered": self.reassessment_triggered}


class FirmwareIntelligence:
    """Tracks firmware per asset/component and fires reassessment hooks."""

    def __init__(self, reassessment_hook: Optional[Callable[[dict[str, Any]], None]] = None) -> None:
        self._states: dict[tuple[str, str], FirmwareState] = {}
        self._changes: list[FirmwareChange] = []
        self._hook = reassessment_hook

    def observe(self, *, asset_id: str, component: str, version: str) -> FirmwareChange | None:
        component = component.upper()
        key = (asset_id, component)
        state = self._states.get(key)
        now = datetime.now(timezone.utc).isoformat()

        if state is None:
            self._states[key] = FirmwareState(asset_id=asset_id,
                                              component=component,
                                              current=version,
                                              changed_at=now)
            return None

        if state.current == version:
            return None

        # firmware change detected (§9)
        state.previous = state.current
        state.current = version
        state.changed_at = now
        change = FirmwareChange(asset_id=asset_id, component=component,
                                previous=state.previous, current=version,
                                timestamp=now)
        self._changes.append(change)

        # targeted crypto re-evaluation (capability reassessment)
        if self._hook is not None:
            self._hook({"asset_id": asset_id, "component": component,
                        "previous": change.previous, "current": version,
                        "type": "firmware_change"})
            change.reassessment_triggered = True
        return change

    def state(self, asset_id: str, component: str) -> Optional[FirmwareState]:
        return self._states.get((asset_id, component.upper()))

    def asset_firmware(self, asset_id: str) -> dict[str, str]:
        return {component: state.current
                for (aid, component), state in self._states.items()
                if aid == asset_id}

    def changes(self) -> list[FirmwareChange]:
        return list(self._changes)
