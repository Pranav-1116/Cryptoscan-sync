"""Host readers (phase H2/H3): the layer that produces a collector context.

A collector without a reader is a schema waiting for a caller to fill it. This
package holds the code that actually looks at a machine — currently Linux
(``/sys``, dmidecode, lsblk, lspci, smartctl) — behind an argv allowlist and a
read-only contract.
"""

from __future__ import annotations

from universal_vendor.hardware.host.snmp_bridge import (
    CredentialLeakRefused,
    NetworkDeviceFacts,
    SnmpHardwareBridge,
    SnmpUnavailable,
)
from universal_vendor.hardware.host.linux import (
    ALLOWED_BINARIES,
    CommandNotAllowed,
    CommandResult,
    HostFacts,
    LinuxHostCollector,
    PathNotAllowed,
    build_argv,
    parse_dmidecode_memory,
    parse_dmidecode_system,
    parse_lsblk,
    parse_lspci,
    parse_smartctl,
    subprocess_runner,
    validate_device,
)

__all__ = [
    "ALLOWED_BINARIES",
    "CredentialLeakRefused",
    "NetworkDeviceFacts",
    "SnmpHardwareBridge",
    "SnmpUnavailable",
    "CommandNotAllowed",
    "CommandResult",
    "HostFacts",
    "LinuxHostCollector",
    "PathNotAllowed",
    "build_argv",
    "parse_dmidecode_memory",
    "parse_dmidecode_system",
    "parse_lsblk",
    "parse_lspci",
    "parse_smartctl",
    "subprocess_runner",
    "validate_device",
]
