"""ZELNX Cloud Discovery Engine — scan modes.

Every scan is read-only unless an explicitly authorized workflow exists.
The default enterprise mode is **INVENTORY_ONLY + CRYPTO_DISCOVERY**:

- ``INVENTORY_ONLY``        — build the org/account/region/resource tree
                              and the full asset inventory (no crypto detail)
- ``CRYPTO_DISCOVERY``      — keys, certificates, PKI, encryption state,
                              network crypto and TLS endpoints on top of the
                              inventory
- ``DEEP_CRYPTO_DISCOVERY`` — adds K8s internals, serverless dependency
                              analysis, IAM crypto access and cross-cloud
                              relationships (still read-only)
- ``CONTINUOUS_MONITORING`` — periodic re-discovery + drift detection
- ``EVENT_DRIVEN``          — consume cloud events to keep the CBOM live

Modes compose: a scan runs with a *set* of modes.  ``DEFAULT_MODES`` is
``{INVENTORY_ONLY, CRYPTO_DISCOVERY}``.
"""

from __future__ import annotations

from enum import Enum


class CloudScanMode(str, Enum):
    INVENTORY_ONLY = "INVENTORY_ONLY"
    CRYPTO_DISCOVERY = "CRYPTO_DISCOVERY"
    DEEP_CRYPTO_DISCOVERY = "DEEP_CRYPTO_DISCOVERY"
    CONTINUOUS_MONITORING = "CONTINUOUS_MONITORING"
    EVENT_DRIVEN = "EVENT_DRIVEN"


SCAN_MODES = frozenset(mode.value for mode in CloudScanMode)
DEFAULT_MODES = frozenset(
    {CloudScanMode.INVENTORY_ONLY, CloudScanMode.CRYPTO_DISCOVERY}
)

# everything the engine is allowed to do is read-only; DEEP adds more
# read-only surfaces (K8s config, IAM policies, cross-cloud relations)
_READ_ONLY = True


def validate_modes(modes: list[str] | set[str] | frozenset[str] | None) -> set[CloudScanMode]:
    """Normalize + validate a mode set; unknown modes raise ``ValueError``."""
    if not modes:
        return set(DEFAULT_MODES)
    parsed: set[CloudScanMode] = set()
    for raw in modes:
        token = str(raw).strip().upper()
        if token not in SCAN_MODES:
            raise ValueError(
                f"unknown cloud scan mode '{token}' (choose from {sorted(SCAN_MODES)})"
            )
        parsed.add(CloudScanMode(token))
    return parsed


def is_read_only(modes: set[CloudScanMode] | None) -> bool:
    """All supported modes are read-only by construction."""
    return _READ_ONLY


def requires_events(modes: set[CloudScanMode]) -> bool:
    return CloudScanMode.EVENT_DRIVEN in modes


def requires_deep(modes: set[CloudScanMode]) -> bool:
    return CloudScanMode.DEEP_CRYPTO_DISCOVERY in modes


def mode_names(modes: set[CloudScanMode] | None) -> list[str]:
    return sorted(mode.value for mode in (modes or set(DEFAULT_MODES)))


def describe(modes: set[CloudScanMode] | None = None) -> dict[str, object]:
    parsed = modes or set(DEFAULT_MODES)
    return {
        "modes": mode_names(parsed),
        "default": mode_names(None),
        "read_only": is_read_only(parsed),
        "deep": requires_deep(parsed),
        "event_driven": requires_events(parsed),
        "note": "All access is read-only unless an explicitly authorized workflow exists.",
    }
