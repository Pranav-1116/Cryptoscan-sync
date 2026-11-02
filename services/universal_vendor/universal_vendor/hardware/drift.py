"""Hardware drift (§8, §9 of the hardware review): what changed, and does it touch crypto?

The estate already had drift for software and for the twin. Hardware drifted in a
weaker way: a fingerprint changed, an event was raised, and the *consequence* —
"the appliance gained ML-DSA", "the firmware moved from 8.2.1 to 8.4 and the
algorithm list did not move with it" — was left to whoever read the timeline.

This module turns two observations of the same asset into classified change
events, in the vocabulary the live hardware pipeline already speaks
(``HardwareEventType`` / ``ChangeClass``):

* ``HARDWARE_CHANGED`` — vendor, model, device type or serial moved. A model
  change is a replacement, not a firmware bump, and must not be reported as one.
* ``FIRMWARE_CHANGED`` — a firmware component's version moved. The *component* is
  named (BIOS, BMC, HSM firmware, TPM firmware), because "firmware changed" on a
  server with four of them is not actionable.
* ``CRYPTO_CAPABILITY_CHANGED`` — the supported-algorithm set moved at all.
* ``PQC_CAPABILITY_ADDED`` / ``PQC_CAPABILITY_REMOVED`` — the movement was in the
  post-quantum set specifically. This is the row a PQC programme reads: an HSM
  that gained ML-KEM is a migration opportunity, and one that *lost* it is an
  incident.
* ``TPM_FIRMWARE_CHANGED`` / ``HSM_CAPABILITY_CHANGED`` — the same change, said
  in the vocabulary of the appliance that made it.

Every change carries ``pqc_affected`` and the evidence ids of both observations,
so a drift row can be traced back to the two records it came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.hardware-drift/1"

#: Algorithms that count as post-quantum for the purposes of the PQC rows. Kept
#: as an explicit set rather than a prefix match: "ML-KEM" and "Kyber" are the
#: same family, "ML" alone would match a marketing string.
PQC_ALGORITHMS = frozenset({
    "ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA", "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F",
    "KYBER", "KYBER-512", "KYBER-768", "KYBER-1024",
    "DILITHIUM", "DILITHIUM-2", "DILITHIUM-3", "DILITHIUM-5",
    "FALCON", "FALCON-512", "FALCON-1024", "SPHINCS+", "HQC", "BIKE",
})

#: Identity fields: a change here is a different appliance, not a changed one.
IDENTITY_FIELDS = ("manufacturer", "model", "device_type", "serial_reference")

#: Severity by event type — a capability change on a security appliance outranks
#: a firmware bump on a switch.
SEVERITY = {
    "HARDWARE_CHANGED": "HIGH",
    "FIRMWARE_CHANGED": "MEDIUM",
    "CRYPTO_CAPABILITY_CHANGED": "MEDIUM",
    "PQC_CAPABILITY_ADDED": "MEDIUM",
    "PQC_CAPABILITY_REMOVED": "HIGH",
    "TPM_FIRMWARE_CHANGED": "MEDIUM",
    "HSM_CAPABILITY_CHANGED": "HIGH",
}


@dataclass
class HardwareChange:
    asset_id: str
    event_type: str
    change_class: str
    detail: dict[str, Any]
    severity: str
    pqc_affected: bool
    evidence: list[str] = field(default_factory=list)
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "asset_id": self.asset_id, "event_type": self.event_type,
                "change_class": self.change_class, "severity": self.severity,
                "pqc_affected": self.pqc_affected, "detail": self.detail,
                "evidence": list(self.evidence), "detected_at": self.detected_at}


def _algorithm_index(observation: Mapping[str, Any]) -> dict[str, str]:
    """``canonical -> as-written`` for every algorithm the observation names.

    Comparison happens on the canonical form ("RSA-2048" and "RSA 2048" are one
    capability); reporting happens on the form the appliance used, because a
    change log that invents a spelling nobody can search for is noise.
    """
    values: Iterable[Any] | None = observation.get("supported_algorithms")
    if not values:
        capabilities = observation.get("crypto_capabilities")
        values = (capabilities if isinstance(capabilities, Iterable)
                  and not isinstance(capabilities, (str, bytes)) else None)
    index: dict[str, str] = {}
    for value in values or ():
        text = str(value).strip()
        if text:
            index.setdefault(text.upper().replace(" ", "-").replace("_", "-"), text)
    return index


def _is_pqc(value: str) -> bool:
    text = value.replace(" ", "-")
    if text in PQC_ALGORITHMS:
        return True
    # "ML-KEM-768@FIPS203" and friends: match a known family prefix
    return any(text.startswith(family + "-") for family in
               ("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "FALCON"))


def _firmware_map(observation: Mapping[str, Any]) -> dict[str, str]:
    firmware = observation.get("firmware")
    if isinstance(firmware, Mapping):
        return {str(k): str(v) for k, v in firmware.items() if v is not None}
    if isinstance(firmware, str) and firmware:
        return {"firmware": firmware}
    return {}


def _algorithms(observation: Mapping[str, Any]) -> set[str]:
    return set(_algorithm_index(observation))


def _evidence_ids(observation: Mapping[str, Any]) -> list[str]:
    history = observation.get("evidence_history")
    if isinstance(history, Iterable) and not isinstance(history, (str, bytes)):
        return [str(item) for item in history]
    single = observation.get("evidence_id")
    return [str(single)] if single else []


def diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[HardwareChange]:
    """Classify what changed between two observations of one asset.

    ``before`` and ``after`` are observation dicts (``HardwareObservation`` or a
    hardware state as the live pipeline stores it). An asset id mismatch raises:
    comparing two different appliances produces a change log that is confidently
    wrong, which is the one outcome a drift feed must never have.
    """
    before_id, after_id = before.get("asset_id"), after.get("asset_id")
    if before_id != after_id:
        raise ValueError(
            f"refusing to diff {before_id!r} against {after_id!r}: two assets are not one "
            "asset's history")

    asset_id = str(after_id)
    evidence = sorted(set(_evidence_ids(before)) | set(_evidence_ids(after)))
    changes: list[HardwareChange] = []

    def add(event_type: str, change_class: str, detail: dict[str, Any],
            pqc_affected: bool = False) -> None:
        changes.append(HardwareChange(asset_id=asset_id, event_type=event_type,
                                      change_class=change_class, detail=detail,
                                      severity=SEVERITY.get(event_type, "INFO"),
                                      pqc_affected=pqc_affected, evidence=evidence))

    # ---- identity ------------------------------------------------------- #
    moved = {name: {"before": before.get(name), "after": after.get(name)}
             for name in IDENTITY_FIELDS
             if (before.get(name) or None) != (after.get(name) or None)}
    if moved:
        add("HARDWARE_CHANGED", "REPLACEMENT" if "model" in moved or "serial_reference" in moved
            else "MODIFICATION", {"fields": moved})

    # ---- firmware, per component ---------------------------------------- #
    previous_firmware, current_firmware = _firmware_map(before), _firmware_map(after)
    previous_tpm = (before.get("tpm") or {}).get("firmware") if isinstance(before.get("tpm"), Mapping) else None
    current_tpm = (after.get("tpm") or {}).get("firmware") if isinstance(after.get("tpm"), Mapping) else None
    if previous_tpm or current_tpm:
        previous_firmware = {**previous_firmware, "TPM": str(previous_tpm or "")}
        current_firmware = {**current_firmware, "TPM": str(current_tpm or "")}

    firmware_moved = {component: {"before": previous_firmware.get(component),
                                  "after": current_firmware.get(component)}
                      for component in set(previous_firmware) | set(current_firmware)
                      if previous_firmware.get(component, "") != current_firmware.get(component, "")}
    if firmware_moved:
        add("FIRMWARE_CHANGED", "FIRMWARE_CHANGE", {"components": firmware_moved})
        if any(name.upper() == "TPM" for name in firmware_moved):
            add("TPM_FIRMWARE_CHANGED", "FIRMWARE_CHANGE",
                {"components": {k: v for k, v in firmware_moved.items() if k.upper() == "TPM"}})

    # ---- crypto capability ---------------------------------------------- #
    previous_index, current_index = _algorithm_index(before), _algorithm_index(after)
    added = sorted(current_index[key] for key in set(current_index) - set(previous_index))
    removed = sorted(previous_index[key] for key in set(previous_index) - set(current_index))
    if added or removed:
        add("CRYPTO_CAPABILITY_CHANGED", "CAPABILITY_CHANGE",
            {"added": added, "removed": removed},
            pqc_affected=any(_is_pqc(a) for a in added + removed))
        pqc_added = sorted(a for a in added if _is_pqc(a))
        pqc_removed = sorted(a for a in removed if _is_pqc(a))
        if pqc_added:
            add("PQC_CAPABILITY_ADDED", "CAPABILITY_CHANGE", {"algorithms": pqc_added},
                pqc_affected=True)
        if pqc_removed:
            add("PQC_CAPABILITY_REMOVED", "CAPABILITY_CHANGE", {"algorithms": pqc_removed},
                pqc_affected=True)
        # the appliance's own vocabulary, when the asset is one
        if str(after.get("device_type") or "").lower() == "hsm":
            add("HSM_CAPABILITY_CHANGED", "CAPABILITY_CHANGE",
                {"added": added, "removed": removed},
                pqc_affected=any(_is_pqc(a) for a in added + removed))

    return changes


def summarise(changes: Iterable[HardwareChange]) -> dict[str, Any]:
    """Aggregate for a dashboard: counts by class, and the PQC signal on its own."""
    collected = list(changes)
    by_class: dict[str, int] = {}
    by_event: dict[str, int] = {}
    for change in collected:
        by_class[change.change_class] = by_class.get(change.change_class, 0) + 1
        by_event[change.event_type] = by_event.get(change.event_type, 0) + 1
    return {
        "total": len(collected),
        "by_change_class": by_class,
        "by_event": by_event,
        "pqc_changes": sum(1 for change in collected if change.pqc_affected),
        "highest_severity": next((level for level in ("CRITICAL", "HIGH", "MEDIUM", "INFO")
                                  if any(change.severity == level for change in collected)), "INFO"),
        "assets": sorted({change.asset_id for change in collected}),
    }
