"""Hardware crypto capability engine (§10).

Universal capability model: AES, SHA-2, SHA-3, RSA, ECC, ECDSA, ECDH, RNG,
secure key storage, PQC/hybrid. The engine SEPARATES:

    supported by hardware   (the silicon can do it)
    actually used by software/configuration (the estate actually uses it)

That distinction is critical — AES-NI present does not mean TLS uses it.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_vendor.hardware.models import CryptoCapability

_CAPABILITY_FIELDS = (
    "aes", "sha2", "sha3", "rsa", "ecc", "ecdsa", "ecdh", "rng",
    "secure_key_storage", "pqc_hybrid",
)


class CryptoCapabilityEngine:
    """Per-asset capability model with supported-vs-used separation."""

    def __init__(self) -> None:
        self._hardware: dict[str, CryptoCapability] = {}   # what the hardware supports
        self._used: dict[str, set[str]] = {}               # what software/config actually uses

    def record_hardware(self, asset_id: str, capability: CryptoCapability) -> None:
        self._hardware[asset_id] = capability

    def record_hardware_from_dict(self, asset_id: str, data: dict[str, Any]) -> None:
        supported = [str(a) for a in data.get("supported_algorithms") or []]
        incoming_fields = {name: bool(data.get(name, False)) for name in _CAPABILITY_FIELDS}
        # Empty capability containers are not observations. This matters for
        # plugins that expose a capability endpoint even when it returned no
        # algorithm list: UNKNOWN is more accurate than known-all-false.
        if not any(incoming_fields.values()) and not supported:
            return
        previous = self._hardware.get(asset_id)
        fields = {
            name: incoming_fields[name] or bool(getattr(previous, name, False))
            for name in _CAPABILITY_FIELDS
        }
        supported = sorted(set(supported) | set(getattr(previous, "supported_algorithms", []) or []))
        used = sorted(set(str(a) for a in data.get("used_algorithms") or [])
                      | set(getattr(previous, "used_algorithms", []) or []))
        self._hardware[asset_id] = CryptoCapability(
            **fields, supported_algorithms=supported, used_algorithms=used)

    def record_usage(self, asset_id: str, algorithms: list[str]) -> None:
        self._used.setdefault(asset_id, set()).update(algorithms)

    def capability(self, asset_id: str) -> Optional[CryptoCapability]:
        return self._hardware.get(asset_id)

    def supported_but_unused(self, asset_id: str) -> list[str]:
        """Hardware capabilities with no software evidence of use (§5, §10)."""
        cap = self._hardware.get(asset_id)
        if cap is None:
            return []
        supported = set(cap.supported_algorithms)
        used = self._used.get(asset_id, set())
        return sorted(supported - used)

    def summary(self, asset_id: str) -> dict[str, Any]:
        cap = self._hardware.get(asset_id)
        if cap is None:
            return {"asset_id": asset_id, "known": False}
        return {
            "asset_id": asset_id,
            "known": True,
            "hardware_supported": cap.to_dict(),
            "software_used": sorted(self._used.get(asset_id, set())),
            "supported_but_unused": self.supported_but_unused(asset_id),
        }

    def assets(self) -> list[str]:
        return sorted(set(self._hardware) | set(self._used))


class CapabilityRegistry:
    """Catalog of what each hardware class supports (lookup by model)."""

    def __init__(self) -> None:
        self._entries: dict[str, dict[str, Any]] = {}

    def register(self, model_key: str, capability: dict[str, Any]) -> None:
        self._entries[model_key.lower()] = capability

    def lookup(self, model: str) -> Optional[dict[str, Any]]:
        return self._entries.get(model.lower())

    def entries(self) -> list[dict[str, Any]]:
        return list(self._entries.values())

    def count(self) -> int:
        return len(self._entries)
