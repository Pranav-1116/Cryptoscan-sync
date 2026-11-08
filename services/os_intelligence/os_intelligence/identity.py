"""OS/kernel identity parsing (docs/os-kernel-intelligence/
01_PRODUCT_SPEC.md §4): uname output, os-release, cmdline, taints.

Every field can be absent — absent means UNAVAILABLE (recorded), never
inferred (§2.1). `environment_development_only` records that a
successful single-host collection is not enterprise qualification
(§12); it is reported as a scope caveat, never as a verdict on the
host.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .evidence import CoverageReport


@dataclass
class OSIdentity:
    kernel_name: str = ""
    kernel_release: str = ""
    kernel_version: str = ""
    machine: str = ""
    os_pretty_name: str = ""
    os_id: str = ""
    os_version_id: str = ""
    arch: str = ""
    cmdline: str = ""
    tainted_flags: str = ""
    tainted_meanings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "kernel_name": self.kernel_name or "unknown",
            "kernel_release": self.kernel_release or "unknown",
            "kernel_version": self.kernel_version or "unknown",
            "machine": self.machine or "unknown",
            "os_pretty_name": self.os_pretty_name or "unknown",
            "os_id": self.os_id or "unknown",
            "os_version_id": self.os_version_id or "unknown",
            "arch": self.arch or self.machine or "unknown",
            "cmdline": self.cmdline or "unavailable",
            "tainted_flags": self.tainted_flags or "0",
            "tainted_meanings": self.tainted_meanings,
            "environment_development_only": True,
            "qualification_note": "this inventory is evidence for THIS "
                                  "host only — it is not an enterprise "
                                  "qualification result (§12); one "
                                  "successful collection is never fleet "
                                  "coverage",
            "notes": self.notes,
        }


# Linux kernel taint flag meanings (kernel.org Documentation/admin-guide).
_TAINT_BITS = {
    0: "PROPRIETARY_MODULE",
    1: "FORCED_MODULE",
    2: "SMP_UNSAFE",
    3: "FORCED_RMMOD",
    4: "MACHINE_CHECK",
    5: "BAD_PAGE",
    6: "USER",
    7: "DIE",
    8: "OVERRIDDEN_ACPI_TABLE",
    9: "WARN",
    10: "FIRMWARE_WORKAROUND",
    11: "OUT_OF_TREE_MODULE",
    12: "UNSIGNED_MODULE",
    13: "SOFTLOCKUP_LIVEPATCH",
    14: "LIVEPATCH",
}


def parse_os_release(text: str) -> Dict[str, str]:
    """Parse /etc/os-release key=value content (bounded)."""
    result: Dict[str, str] = {}
    for line in text.splitlines()[:64]:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def parse_uname_line(line: str) -> Tuple[str, str, str, str]:
    """Parse `uname -a` output into (system, release, version, machine).

    `uname -a` format: system hostname release version ... machine os
    e.g. Linux host 6.1.158+ #1 SMP ... x86_64 GNU/Linux
    Also accepts /proc/version content ('Linux version ...') and bare
    `uname -r` content. Unparseable content yields empty fields — never
    guessed (§2.1)."""
    parts = line.split()
    if not parts:
        return "", "", "", ""
    if parts[0] == "Linux" and len(parts) > 1 and parts[1] == "version":
        # /proc/version: Linux version <release> (user@host) (gcc ...)
        release = parts[2] if len(parts) > 2 else ""
        machine = next((p for p in parts
                        if p in ("x86_64", "aarch64", "armv7l", "ppc64le",
                                 "s390x", "riscv64", "i686")), "")
        return "Linux", release, "", machine
    if len(parts) == 1:
        # bare `uname -r`
        return "Linux", parts[0], "", ""
    if len(parts) < 4:
        return "", "", "", ""
    system = parts[0]
    release = parts[2]
    machine = parts[-2] if len(parts) >= 5 else ""
    version = " ".join(parts[3:-2]) if len(parts) > 5 else ""
    return system, release, version, machine


def parse_taints(value: str) -> Tuple[str, List[str]]:
    """Decode /proc/sys/kernel/tainted — an integer bitmask."""
    value = value.strip()
    if not value:
        return "0", []
    try:
        number = int(value)
    except ValueError:
        return value, [f"taint value {value!r} is not an integer — "
                       "meanings unknown, never guessed"]
    meanings = [name for bit, name in sorted(_TAINT_BITS.items())
                if number & (1 << bit)]
    return str(number), meanings


def collect_identity(captured: Dict[str, str]) -> OSIdentity:
    """Build OSIdentity from captured raw outputs. Keys expected:
    uname, os_release, cmdline, tainted — each optional; missing keys
    are UNAVAILABLE, never inferred (§2.1)."""
    identity = OSIdentity()
    if "uname" in captured:
        system, release, version, machine = parse_uname_line(captured["uname"])
        identity.kernel_name = system
        identity.kernel_release = release
        identity.kernel_version = version
        identity.machine = machine
    else:
        identity.notes.append("uname unavailable — kernel fields "
                              "recorded as unknown (§2.1)")
    if "os_release" in captured:
        data = parse_os_release(captured["os_release"])
        identity.os_pretty_name = data.get("PRETTY_NAME", "")
        identity.os_id = data.get("ID", "")
        identity.os_version_id = data.get("VERSION_ID", "")
    else:
        identity.notes.append("os-release unavailable — distribution "
                              "fields recorded as unknown (§2.1)")
    identity.cmdline = captured.get("cmdline", "")
    if "cmdline" not in captured:
        identity.notes.append("cmdline unavailable — recorded as "
                              "unavailable (§2.1)")
    number, meanings = parse_taints(captured.get("tainted", "0"))
    identity.tainted_flags = number
    identity.tainted_meanings = meanings
    if meanings:
        identity.notes.append(
            f"kernel tainted flags set: {', '.join(meanings)} — tainted "
            "means the running kernel carries state outside the "
            "supported pristine condition (e.g. out-of-tree or "
            "unsigned modules); it is NOT a defect verdict (§1: finding, "
            "not verdict)")
    identity.arch = platform.machine() or identity.machine
    return identity
