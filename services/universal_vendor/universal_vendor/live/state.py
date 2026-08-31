"""Live Vendor Asset State Engine (24/7 spec §3).

Every vendor asset keeps a persistent state: current configuration state,
previous state, first/last seen, last verified, last crypto scan, last
configuration/firmware change, monitoring status and evidence history.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from universal_vendor.live.events import ChangeType, EventType, UniversalVendorEvent


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MonitoringStatus(str):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    STALE = "STALE"
    REMOVED = "REMOVED"


@dataclass
class VendorAssetState:
    asset_id: str
    vendor: str
    product: str
    product_version: Optional[str] = None
    asset_type: str = "other"

    # configuration state (fingerprints, see live/fingerprint.py)
    current_config_hash: Optional[str] = None
    previous_config_hash: Optional[str] = None
    current_config_snapshot: dict[str, Any] = field(default_factory=dict)

    # firmware
    firmware: Optional[str] = None
    previous_firmware: Optional[str] = None

    # crypto summary (last crypto scan)
    crypto_scan: dict[str, Any] = field(default_factory=dict)

    # timestamps
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    last_verified: Optional[str] = None
    last_crypto_scan: Optional[str] = None
    last_configuration_change: Optional[str] = None
    last_firmware_change: Optional[str] = None

    monitoring_status: str = MonitoringStatus.ACTIVE
    evidence_history: list[str] = field(default_factory=list)  # evidence hashes

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "vendor": self.vendor,
            "product": self.product,
            "product_version": self.product_version,
            "asset_type": self.asset_type,
            "current_config_hash": self.current_config_hash,
            "previous_config_hash": self.previous_config_hash,
            "firmware": self.firmware,
            "previous_firmware": self.previous_firmware,
            "crypto_scan": self.crypto_scan,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_verified": self.last_verified,
            "last_crypto_scan": self.last_crypto_scan,
            "last_configuration_change": self.last_configuration_change,
            "last_firmware_change": self.last_firmware_change,
            "monitoring_status": self.monitoring_status,
            "evidence_history": list(self.evidence_history),
        }


class LiveAssetStateEngine:
    """Applies canonical events to persistent asset states.

    Outcome per event: NEW_ASSET | CHANGED_ASSET | REMOVED_ASSET | NO_CHANGE
    (spec §3 flow).
    """

    def __init__(self) -> None:
        self._states: dict[str, VendorAssetState] = {}

    # ── queries ──────────────────────────────────────────────────────

    def get(self, asset_id: str) -> Optional[VendorAssetState]:
        return self._states.get(asset_id)

    def all(self) -> list[VendorAssetState]:
        return list(self._states.values())

    def count(self) -> int:
        return len(self._states)

    # ── event application ────────────────────────────────────────────

    def apply(self, event: UniversalVendorEvent) -> str:
        """Apply one canonical event. Returns NEW_ASSET / CHANGED_ASSET /
        REMOVED_ASSET / NO_CHANGE."""
        asset_id = event.asset_id or f"{event.vendor}:{event.product}"
        state = self._states.get(asset_id)

        if event.event_type == EventType.ASSET_REMOVED:
            if state is None:
                return "NO_CHANGE"
            state.monitoring_status = MonitoringStatus.REMOVED
            state.last_seen = event.timestamp
            return "REMOVED_ASSET"

        if state is None:
            state = VendorAssetState(
                asset_id=asset_id, vendor=event.vendor, product=event.product,
                product_version=event.product_version, asset_type=event.asset_type,
                first_seen=event.timestamp, last_seen=event.timestamp,
                monitoring_status=MonitoringStatus.ACTIVE,
            )
            self._states[asset_id] = state
            if event.evidence_reference:
                state.evidence_history.append(event.evidence_reference)
            return "NEW_ASSET"

        # existing asset — detect what changed
        state.last_seen = event.timestamp
        state.product_version = event.product_version or state.product_version
        changed = False

        if event.event_type == EventType.FIRMWARE_CHANGED:
            firmware = (event.vendor_metadata or {}).get("firmware")
            if firmware and firmware != state.firmware:
                state.previous_firmware = state.firmware
                state.firmware = firmware
                state.last_firmware_change = event.timestamp
                changed = True

        if event.event_type in (EventType.CONFIG_CHANGED, EventType.CRYPTO_CHANGED,
                                EventType.TLS_CHANGED, EventType.IPSEC_CHANGED,
                                EventType.IKE_CHANGED, EventType.SSH_CHANGED,
                                EventType.CRYPTO_POLICY_CHANGED,
                                EventType.TRUST_STORE_CHANGED,
                                EventType.VPN_CHANGED, EventType.AAA_CHANGED,
                                EventType.KEY_CHANGED, EventType.CA_CHANGED,
                                EventType.SIGNATURE_ALGORITHM_CHANGED,
                                EventType.HSM_CONFIGURATION_CHANGED,
                                EventType.HSM_CRYPTO_CAPABILITY_CHANGED,
                                EventType.HSM_KEY_METADATA_CHANGED,
                                EventType.HSM_CERTIFICATE_CHANGED,
                                EventType.INTERFACE_CHANGED,
                                EventType.ROUTING_CHANGED,
                                EventType.ADMIN_CONFIG_CHANGED):
            if event.change_type != ChangeType.OBSERVED:
                state.last_configuration_change = event.timestamp
                changed = True

        if event.event_type == EventType.CRYPTO_CHANGED:
            state.last_crypto_scan = event.timestamp
            state.crypto_scan = dict(event.vendor_metadata)

        if event.evidence_reference:
            state.evidence_history.append(event.evidence_reference)

        return "CHANGED_ASSET" if changed else "NO_CHANGE"

    def update_config_hash(self, asset_id: str, config_hash: str,
                           snapshot: dict[str, Any] | None = None,
                           *, timestamp: Optional[str] = None) -> None:
        state = self._states.get(asset_id)
        if state is None:
            return
        if config_hash != state.current_config_hash:
            state.previous_config_hash = state.current_config_hash
            state.current_config_hash = config_hash
            if snapshot is not None:
                state.current_config_snapshot = snapshot
            state.last_configuration_change = timestamp or _now()

    def mark_verified(self, asset_id: str, *, timestamp: Optional[str] = None) -> None:
        state = self._states.get(asset_id)
        if state is not None:
            state.last_verified = timestamp or _now()

    def mark_crypto_scanned(self, asset_id: str, summary: dict[str, Any],
                            *, timestamp: Optional[str] = None) -> None:
        state = self._states.get(asset_id)
        if state is not None:
            state.crypto_scan = dict(summary)
            state.last_crypto_scan = timestamp or _now()

    def mark_stale(self, *, threshold_seconds: int = 3600) -> list[str]:
        """Flag assets not seen recently as STALE. Returns affected ids."""
        stale: list[str] = []
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=threshold_seconds)
        for asset_id, state in self._states.items():
            if state.monitoring_status == MonitoringStatus.ACTIVE:
                try:
                    last = datetime.fromisoformat(state.last_seen)
                except ValueError:
                    continue
                if last < cutoff:
                    state.monitoring_status = MonitoringStatus.STALE
                    stale.append(asset_id)
        return stale
