"""Live hardware monitoring + 24/7 state + drift (§15, §16, §17).

§15 monitor: events / telemetry / polling → hardware state → change
detection → targeted re-discovery. Event types: DEVICE_ADDED, DEVICE_REMOVED,
FIRMWARE_CHANGED, HARDWARE_CHANGED, TPM_CHANGED, HSM_CHANGED, NIC_CHANGED,
CRYPTO_CAPABILITY_CHANGED.

§16 every asset keeps current/previous state, first/last seen, last
verified, last firmware check, last crypto check, last change, evidence
history.

§17 drift: EXPECTED vs CURRENT — unexpected device, unexpected replacement,
firmware/BIOS/NIC/TPM/HSM/crypto-capability drift. Example: TPM expected
present, current unavailable → SECURITY_HARDWARE_DRIFT.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from universal_vendor.hardware.fingerprint import FingerprintTracker, HardwareFingerprint
from universal_vendor.hardware.models import (
    HardwareDriftType,
    HardwareState,
    HardwareType,
)
from universal_vendor.hardware.tpm import TpmInfo, TpmScanner

_HARDWARE_EVENT_TYPES = (
    "DEVICE_ADDED", "DEVICE_REMOVED", "FIRMWARE_CHANGED", "HARDWARE_CHANGED",
    "TPM_CHANGED", "HSM_CHANGED", "NIC_CHANGED", "CRYPTO_CAPABILITY_CHANGED",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LiveHardwareMonitor:
    """Collects hardware events from connectors/telemetry/polling."""

    def __init__(self) -> None:
        self._sources: list[Any] = []

    def register(self, source: Any) -> Any:
        """source: object with .collect() returning event dicts."""
        self._sources.append(source)
        return source

    def collect(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for source in self._sources:
            try:
                events.extend(source.collect())
            except Exception as exc:  # one broken source never kills the loop
                events.append({"event_type": "HARDWARE_CHANGED",
                               "detail": {"error": f"{type(exc).__name__}: {exc}"}})
        return events


class HardwareStateEngine:
    """§16 — persistent 24/7 per-asset hardware state."""

    def __init__(self) -> None:
        self._states: dict[str, HardwareState] = {}

    def get(self, asset_id: str) -> Optional[HardwareState]:
        return self._states.get(asset_id)

    def all(self) -> list[HardwareState]:
        return list(self._states.values())

    def count(self) -> int:
        return len(self._states)

    def apply_event(self, event: dict[str, Any]) -> str:
        """Apply a hardware event; returns NEW / CHANGED / REMOVED / NO_CHANGE."""
        event_type = event.get("event_type")
        assert event_type in _HARDWARE_EVENT_TYPES, f"unknown hardware event {event_type}"
        asset_id = str(event.get("asset_id") or "unknown")
        now = _now()
        state = self._states.get(asset_id)

        if event_type == "DEVICE_REMOVED":
            if state is None:
                return "NO_CHANGE"
            state.last_seen = now
            state.last_change = f"DEVICE_REMOVED:{now}"
            return "REMOVED"

        if state is None:
            state = HardwareState(
                asset_id=asset_id,
                manufacturer=str(event.get("manufacturer") or ""),
                model=str(event.get("model") or ""),
                device_type=str(event.get("device_type") or HardwareType.OTHER.value),
                first_seen=now, last_seen=now,
            )
            self._states[asset_id] = state
            state.last_change = f"{event_type}:{now}"
            return "NEW"

        state.last_seen = now
        state.last_change = f"{event_type}:{now}"
        if event_type == "FIRMWARE_CHANGED":
            state.last_firmware_check = now
            component = str(event.get("component") or "BIOS")
            version = str(event.get("version") or "")
            state.firmware[component] = version
        if event_type in ("TPM_CHANGED", "HSM_CHANGED", "NIC_CHANGED",
                          "CRYPTO_CAPABILITY_CHANGED"):
            state.last_crypto_check = now
        return "CHANGED"

    def mark_verified(self, asset_id: str, *, timestamp: Optional[str] = None) -> None:
        state = self._states.get(asset_id)
        if state is not None:
            state.last_verified = timestamp or _now()

    def update_fingerprint(self, asset_id: str, fingerprint_hash: str) -> None:
        state = self._states.get(asset_id)
        if state is None:
            return
        if fingerprint_hash != state.current_fingerprint:
            state.previous_fingerprint = state.current_fingerprint
            state.current_fingerprint = fingerprint_hash

    def record_evidence(self, asset_id: str, evidence_id: str) -> None:
        state = self._states.get(asset_id)
        if state is not None:
            state.evidence_history.append(evidence_id)


class HardwareDriftEngine:
    """§17 — EXPECTED vs CURRENT hardware state."""

    def __init__(self) -> None:
        self._expected: dict[str, dict[str, Any]] = {}
        self._history: list[dict[str, Any]] = []
        self._tpm_scanner = TpmScanner()

    def set_expected(self, asset_id: str, state: dict[str, Any]) -> None:
        self._expected[asset_id] = state

    def evaluate(self, asset_id: str, current: dict[str, Any],
                 *, fingerprint: Optional[HardwareFingerprint] = None) -> dict[str, Any]:
        expected = self._expected.get(asset_id)
        if expected is None:
            return {"asset_id": asset_id, "state": HardwareDriftType.NO_CHANGE.value,
                    "reason": "no expected state defined"}

        verdicts: list[str] = []

        # TPM drift (§6/§17 example)
        expected_tpm = expected.get("tpm")
        current_tpm = current.get("tpm")
        if expected_tpm is not None:
            drift = self._tpm_scanner.drift(
                TpmInfo(**{k: v for k, v in expected_tpm.items() if k in
                           ("present", "version", "manufacturer", "firmware",
                            "capabilities", "supported_algorithms",
                            "pcr_capabilities", "secure_boot_relationship")}),
                TpmInfo(**{k: v for k, v in (current_tpm or {}).items() if k in
                           ("present", "version", "manufacturer", "firmware",
                            "capabilities", "supported_algorithms",
                            "pcr_capabilities", "secure_boot_relationship")}),
            )
            if drift:
                verdicts.append(drift)

        # firmware drift
        expected_fw = expected.get("firmware") or {}
        current_fw = current.get("firmware") or {}
        for component, version in expected_fw.items():
            if current_fw.get(component) != version:
                verdicts.append("FIRMWARE_DRIFT" if component != "BIOS" else "BIOS_DRIFT")

        # unexpected device / replacement
        if expected.get("present") and not current.get("present"):
            verdicts.append("UNEXPECTED_DEVICE")
        if (expected.get("model") and current.get("model")
                and expected["model"] != current["model"]):
            verdicts.append("UNEXPECTED_REPLACEMENT")

        # fingerprint drift
        if fingerprint is not None:
            tracker_check = self._fingerprint_changed(asset_id, fingerprint)
            if tracker_check:
                verdicts.append("CRYPTO_CAPABILITY_DRIFT")

        state = verdicts[0] if verdicts else HardwareDriftType.NO_CHANGE.value
        record = {"asset_id": asset_id, "state": state,
                  "drift_types": verdicts,
                  "reason": "; ".join(verdicts) if verdicts else "no drift"}
        self._history.append(record)
        return record

    def _fingerprint_changed(self, asset_id: str, fingerprint: HardwareFingerprint) -> bool:
        tracker = getattr(self, "_tracker", None)
        if tracker is None:
            self._tracker = FingerprintTracker()
        result = self._tracker.observe(asset_id, fingerprint)
        return bool(result.get("changed"))

    def history(self) -> list[dict[str, Any]]:
        return list(self._history)
