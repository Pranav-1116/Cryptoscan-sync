"""Universal Hardware Scanner.

A read-only hardware intelligence platform covering the full lifecycle from
physical discovery (agent / network / API, never a single source of truth)
through fingerprinting, identity resolution, capability discovery, firmware
intelligence, correlation, lifecycle, risk, evidence chaining, HBOM/CBOM,
live monitoring, alert correlation, OT/ICS passive-first mode, mandatory
safety controls, distributed edge collection, and the hardware plugin
framework.
"""

from __future__ import annotations

from universal_vendor.hardware.models import (
    CloudVisibility,
    CpuInfo,
    DiscoveryMethod,
    FirmwareComponent,
    FirmwareState,
    HardwareConfidence,
    HardwareDriftType,
    HardwareIdentity,
    HardwareObservation,
    HardwareState,
    HardwareType,
    TpmInfo,
)

__all__ = [
    "CloudVisibility",
    "CpuInfo",
    "DiscoveryMethod",
    "FirmwareComponent",
    "FirmwareState",
    "HardwareConfidence",
    "HardwareDriftType",
    "HardwareIdentity",
    "HardwareObservation",
    "HardwareState",
    "HardwareType",
    "TpmInfo",
]
