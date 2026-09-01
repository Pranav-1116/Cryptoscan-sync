"""Historical hardware timeline (§16).

Every hardware event is appended to an immutable journal. From the journal
we can answer the enterprise question:

    "Show hardware state at 2026-08-31 12:00"

by replaying events up to that instant through a fresh state engine. The
current state is just the replay prefix ending at *now* — the event history
reconstructs any past state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from universal_vendor.hardware.live.state import HardwareStateEngine


def _parse(ts: str) -> datetime:
    dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class HardwareTimeline:
    """Append-only hardware event journal + point-in-time reconstruction."""

    def __init__(self) -> None:
        self._journal: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> None:
        """Append one event (already shaped as a state event)."""
        entry = dict(event)
        entry.setdefault("observed_at", datetime.now(timezone.utc).isoformat())
        self._journal.append(entry)

    # ── queries ───────────────────────────────────────────────────────

    def events(self, asset_id: Optional[str] = None,
               *, after: Optional[str] = None) -> list[dict[str, Any]]:
        rows = self._journal
        if asset_id:
            rows = [r for r in rows if r.get("asset_id") == asset_id]
        if after:
            rows = [r for r in rows if _parse(str(r["observed_at"])) > _parse(after)]
        return list(rows)

    def count(self, asset_id: Optional[str] = None) -> int:
        return len(self.events(asset_id))

    def state_at(self, asset_id: str, at: str) -> Optional[dict[str, Any]]:
        """Reconstruct the asset's state exactly as of ``at`` (§16).

        Replay: sort journal events by observed_at, apply those <= ``at``
        to a fresh state engine with the event's own timestamp, return the
        resulting state. Deterministic and tamper-relevant (the journal is
        the only input).
        """
        at_dt = _parse(at)
        rows = [r for r in self._journal if r.get("asset_id") == asset_id]
        rows.sort(key=lambda r: _parse(str(r["observed_at"])))
        engine = HardwareStateEngine()
        for row in rows:
            if _parse(str(row["observed_at"])) > at_dt:
                break
            engine.apply_event(row, timestamp=str(row["observed_at"]))
        state = engine.get(asset_id)
        return state.to_dict() if state is not None else None

    def timeline(self, asset_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Human-facing timeline (§16 example): time + event + summary."""
        out = []
        for row in sorted(self._journal, key=lambda r: str(r["observed_at"])):
            if asset_id and row.get("asset_id") != asset_id:
                continue
            etype = row.get("event_type", "?")
            summary = _summarize(etype, row)
            out.append({
                "timestamp": row["observed_at"],
                "event_type": etype,
                "asset_id": row.get("asset_id"),
                "summary": summary,
            })
        return out

    def rebuild_state(self) -> dict[str, Any]:
        """Replay the full journal into a current-state engine (used to
        restore the live state after a restart — the journal IS the truth)."""
        engine = HardwareStateEngine()
        for row in sorted(self._journal, key=lambda r: str(r["observed_at"])):
            engine.apply_event(row, timestamp=str(row["observed_at"]))
        return {s.asset_id: s.to_dict() for s in engine.all()}


def _summarize(event_type: str, row: dict[str, Any]) -> str:
    asset = str(row.get("asset_id") or "?")
    component = str(row.get("component") or "")
    version = str(row.get("version") or "")
    mapping = {
        "HARDWARE_DISCOVERED": f"Server discovered: {asset}",
        "DEVICE_ADDED": f"Server discovered: {asset}",
        "HARDWARE_REMOVED": f"Server removed: {asset}",
        "DEVICE_REMOVED": f"Server removed: {asset}",
        "HARDWARE_REPLACED": f"Hardware replaced: {asset}",
        "HARDWARE_CHANGED": f"Hardware changed: {asset}",
        "FIRMWARE_CHANGED": f"Firmware changed ({component}): {asset}",
        "BIOS_CHANGED": f"BIOS changed: {asset}",
        "UEFI_CHANGED": f"UEFI changed: {asset}",
        "BMC_CHANGED": f"BMC changed: {asset}",
        "NIC_CHANGED": f"NIC changed: {asset}",
        "STORAGE_CHANGED": f"Storage changed: {asset}",
        "CRYPTO_CAPABILITY_CHANGED": f"Crypto capability reassessed: {asset}",
        "HARDWARE_CAPABILITY_CHANGED": f"Hardware capability changed: {asset}",
        "TPM_CHANGED": f"TPM state changed: {asset}",
        "TPM_AVAILABLE": f"TPM available: {asset}",
        "TPM_UNAVAILABLE": f"TPM unavailable: {asset}",
        "TPM_CONFIGURATION_CHANGED": f"TPM configuration changed: {asset}",
        "TPM_FIRMWARE_CHANGED": f"TPM firmware changed: {asset}",
        "HSM_CHANGED": f"HSM changed: {asset}",
        "HSM_ONLINE": f"HSM online: {asset}",
        "HSM_OFFLINE": f"HSM offline: {asset}",
        "HSM_CAPABILITY_CHANGED": f"HSM capability changed: {asset}",
        "HSM_CONFIGURATION_CHANGED": f"HSM configuration changed: {asset}",
    }
    base = mapping.get(event_type, f"Event {event_type}: {asset}")
    if version:
        base = f"{base} -> {version}"
    return base
