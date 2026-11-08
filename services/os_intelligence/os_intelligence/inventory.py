"""Linux OS inventory parsers: kernel modules, kernel configuration
flags, storage encryption metadata, hardware trust facts
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §5).

All parsers are bounded and fail-safe. A source that cannot be read is
an UNAVAILABLE source (CoverageReport) — never zeros, never "absent"
(§2.1). Disk-encryption metadata is metadata only: no recovery keys,
no key files, no secrets are ever collected (§7).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

MAX_MODULES = 2048
MAX_LINES = 20000

# Kernel configuration flags relevant to the OS-CRYPTO rules (§5).
TRACKED_CONFIG_FLAGS = (
    "CONFIG_CRYPTO_API",
    "CONFIG_CRYPTO_AES",
    "CONFIG_CRYPTO_RSA",
    "CONFIG_CRYPTO_SHA256",
    "CONFIG_CRYPTO_USER_API",
    "CONFIG_CRYPTO_USER_API_HASH",
    "CONFIG_CRYPTO_USER_API_SKCIPHER",
    "CONFIG_CRYPTO_USER_API_RNG",
    "CONFIG_CRYPTO_JITTERENTROPY",
    "CONFIG_CRYPTO_FIPS",
    "CONFIG_MODULE_SIG",
    "CONFIG_MODULE_SIG_FORCE",
    "CONFIG_MODULE_SIG_ALL",
    "CONFIG_INTEGRITY",
    "CONFIG_IMA",
    "CONFIG_IMA_APPRAISE",
    "CONFIG_IMA_ARCH_POLICY",
    "CONFIG_SECURITY_SELINUX",
    "CONFIG_SECURITY_APPARMOR",
    "CONFIG_LSM",
    "CONFIG_RANDOM_TRUST_CPU",
    "CONFIG_RANDOM_TRUST_BOOTLOADER",
    "CONFIG_CRYPTO_MANAGER_DISABLE_TESTS",
)


@dataclass
class KernelModule:
    name: str
    size: Optional[int] = None
    refcount: Optional[int] = None
    used_by: List[str] = field(default_factory=list)
    state: str = ""
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "size": self.size,
            "refcount": self.refcount,
            "used_by": self.used_by,
            "state": self.state or "unknown",
            "notes": self.notes,
        }


@dataclass
class StorageEncryptionFact:
    device: str
    fstype: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "device": self.device,
            "fstype": self.fstype or "unavailable",
            "metadata": self.metadata,
            "notes": self.notes,
            "note": "disk-encryption METADATA only — no recovery keys, "
                    "no key files and no secrets are collected (§7)",
        }


@dataclass
class HardwareTrustFact:
    subject: str                       # e.g. "tpm", "secure_boot", "rng"
    state: str                         # "present" | "unavailable" | ...
    evidence_class: str = "observed"
    metadata: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "subject": self.subject,
            "state": self.state,
            "evidence_class": self.evidence_class,
            "metadata": self.metadata,
            "notes": self.notes,
        }


_MODULE_NAME = re.compile(r"^[A-Za-z0-9_]+$")


def parse_modules(text: str) -> List[KernelModule]:
    """Parse /proc/modules: `name size refcount used_by state addr`.

    Fail-safe (§14): a line that does not have the exact row shape —
    a valid module name with integer size and refcount — is NOT a
    module row and is skipped entirely. An error message (e.g. a shell
    'cannot open' line) must never parse into a fabricated module."""
    modules: List[KernelModule] = []
    for line in text.splitlines()[:MAX_MODULES]:
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        if not _MODULE_NAME.match(name):
            continue
        try:
            size = int(parts[1])
            refcount = int(parts[2])
        except ValueError:
            # not a /proc/modules row — skip; never fabricate values
            continue
        used_raw = parts[3] if len(parts) > 3 else ""
        used_by = ([u for u in used_raw.split(",") if u]
                   if used_raw not in ("", "-") else [])
        state = parts[4] if len(parts) > 4 else ""
        modules.append(KernelModule(name=name, size=size,
                                    refcount=refcount, used_by=used_by,
                                    state=state))
    return modules


def parse_config_flags(text: str) -> Tuple[Dict[str, str], List[str]]:
    """Parse kernel configuration lines of interest.

    Returns (flags, notes). Flags absent from the captured config are
    simply NOT recorded — absence from a config snapshot is never
    reported as 'disabled' unless the config source itself was
    collected (§2.1: unavailable ≠ disabled)."""
    flags: Dict[str, str] = {}
    notes: List[str] = []
    tracked = set(TRACKED_CONFIG_FLAGS)
    for line in text.splitlines()[:MAX_LINES]:
        line = line.strip()
        if not line or line.startswith("#"):
            # '# CONFIG_X is not set' is a REAL explicit disabled value
            m = re.match(r"^# (CONFIG_[A-Z0-9_]+) is not set$", line)
            if m and m.group(1) in tracked:
                flags[m.group(1)] = "not_set"
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            if key in tracked:
                flags[key] = value.strip()
    return flags, notes


def parse_lsblk(text: str) -> List[StorageEncryptionFact]:
    """Parse `lsblk -f` output for disk-encryption metadata (§5)."""
    facts: List[StorageEncryptionFact] = []
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return facts
    header = lines[0]
    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue
        device = parts[0].lstrip("├─└─").strip() or parts[0]
        fstype = parts[1] if len(parts) > 1 and parts[1] not in ("", "-") else ""
        metadata: Dict[str, str] = {}
        for token in parts[2:]:
            if "=" in token:
                k, _, v = token.partition("=")
                metadata[k] = v
        fact = StorageEncryptionFact(device=device, fstype=fstype,
                                    metadata=metadata)
        if fstype in ("crypto_LUKS", "crypto_LUKS2"):
            fact.notes.append(
                "LUKS container metadata observed — encryption present "
                "at the storage layer; no key material is collected "
                "(§7)")
        elif not fstype:
            fact.notes.append(
                "no filesystem type reported in this view — encryption "
                "state is UNKNOWN for this device, never 'not "
                "encrypted'")
        elif fstype in ("ext4", "ext3", "ext2", "xfs", "btrfs", "vfat",
                        "swap", "squashfs"):
            fact.notes.append(
                "fstype reported without an encryption layer in this "
                "view — whether the block device beneath is encrypted "
                "requires the parent device view; recorded as observed "
                "metadata, never as 'not encrypted'")
        facts.append(fact)
    return facts
