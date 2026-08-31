"""Universal hardware identity resolver (§3).

Every physical device gets a canonical HardwareIdentity. Identity resolution
uses MULTIPLE signals — serial, MAC, DMI UUID, asset tag, BMC, LLDP/CDP,
cloud metadata — never serial numbers alone (virtualized and network
environments expose incomplete or duplicated identifiers).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareType,
)


@dataclass
class IdentitySignal:
    kind: str       # serial | mac | dmi_uuid | asset_tag | bmc | hostname | cloud_resource
    value: str
    source: str
    weight: float = 0.8

    def key(self) -> str:
        return f"{self.kind}:{str(self.value).strip().lower()}"


class HardwareIdentityResolver:
    """Resolves identity signals into canonical asset records.

    Never relies on serial alone: two devices with the same serial (e.g.
    cloned VMs) are disambiguated by other signals; devices with no serial
    still get an identity from MAC/UUID/tag.
    """

    def __init__(self) -> None:
        self._identities: dict[str, HardwareIdentity] = {}
        self._by_signal: dict[str, str] = {}      # signal.key() -> asset_id

    def resolve(self, *, serial: Optional[str] = None, mac: Optional[str] = None,
                dmi_uuid: Optional[str] = None, asset_tag: Optional[str] = None,
                bmc: Optional[str] = None, hostname: Optional[str] = None,
                cloud_resource: Optional[str] = None,
                ) -> Optional[HardwareIdentity]:
        """Resolve by ANY of the registered signal kinds (§3)."""
        candidates = [
            (serial, "serial"), (mac, "mac"), (dmi_uuid, "dmi_uuid"),
            (asset_tag, "asset_tag"), (bmc, "bmc"), (hostname, "hostname"),
            (cloud_resource, "cloud_resource"),
        ]
        for value, kind in candidates:
            if not value:
                continue
            key = f"{kind}:{str(value).strip().lower()}"
            asset_id = self._by_signal.get(key)
            if asset_id:
                return self._identities[asset_id]
        return None

    @staticmethod
    def _kind_key(value: str) -> str:
        """Canonical registry key for a raw signal value (used by attach())."""
        value = str(value).strip().lower()
        if ":" in value and len(value) == 17:
            return f"mac:{value}"
        if value.startswith(("arn:", "/subscriptions/", "projects/")):
            return f"cloud_resource:{value}"
        return f"identity:{value}"

    def register(self, identity: HardwareIdentity,
                 signals: list[IdentitySignal]) -> str:
        """Register an identity with its corroborating signals."""
        asset_id = identity.asset_id
        self._identities[asset_id] = identity
        for signal in signals:
            self._by_signal[signal.key()] = asset_id
        return asset_id

    def attach(self, asset_id: str, signal: IdentitySignal) -> None:
        self._by_signal[signal.key()] = asset_id

    def get(self, asset_id: str) -> Optional[HardwareIdentity]:
        return self._identities.get(asset_id)

    def all(self) -> list[HardwareIdentity]:
        return list(self._identities.values())

    def count(self) -> int:
        return len(self._identities)

    def build_identity(
        self,
        *,
        signals: list[IdentitySignal],
        manufacturer: str,
        model: str,
        device_type: str = HardwareType.OTHER.value,
        firmware: Optional[str] = None,
        environment: Optional[str] = None,
        source: str = "unknown",
    ) -> HardwareIdentity:
        """Build a canonical identity, computing confidence from signal
        corroboration (≥2 distinct kinds → HIGH, 1 → MEDIUM, none → LOW)."""
        kinds = {s.kind for s in signals}
        confidence = HardwareConfidence.HIGH.value if len(kinds) >= 2 \
            else (HardwareConfidence.MEDIUM.value if kinds else HardwareConfidence.LOW.value)
        serial = next((s.value for s in signals if s.kind == "serial"), None)
        return HardwareIdentity(
            asset_id=signals[0].key() if signals else "unknown",
            manufacturer=manufacturer, model=model,
            serial_reference=serial, device_type=device_type,
            firmware=firmware, environment=environment, source=source,
            confidence=confidence,
        )
