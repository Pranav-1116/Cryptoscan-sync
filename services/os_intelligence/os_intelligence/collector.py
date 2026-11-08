"""Linux read-only collector (docs/os-kernel-intelligence/
01_PRODUCT_SPEC.md §15 step 5, Phase 1).

Principles (§2.1, §7, §11):
- read-only OS interfaces by default (Tier 1);
- a failed or denied read is recorded as 'unavailable' or
  'permission_denied' — NEVER treated as disabled, absent, or as
  evidence that a feature does not exist;
- no key material, recovery keys, passwords or session secrets are
  ever collected — metadata only;
- collection never modifies kernel state and never installs modules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .crypto_api import CryptoApiEntry, parse_crypto_api
from .evidence import (COLLECTOR_NAME, COLLECTOR_VERSION, CoverageReport,
                       OSFinding, evidence_digest)
from .identity import OSIdentity, collect_identity
from .inventory import (HardwareTrustFact, KernelModule,
                        StorageEncryptionFact, parse_config_flags,
                        parse_lsblk, parse_modules)

MAX_SOURCE_BYTES = 4 * 1024 * 1024   # bounded reads (§14)


@dataclass
class OSInventory:
    """Complete Phase-1 collection result for one host."""
    host_id: str
    identity: OSIdentity
    crypto_api: List[CryptoApiEntry] = field(default_factory=list)
    crypto_api_notes: List[str] = field(default_factory=list)
    modules: List[KernelModule] = field(default_factory=list)
    config_flags: Dict[str, str] = field(default_factory=dict)
    storage: List[StorageEncryptionFact] = field(default_factory=list)
    hardware_trust: List[HardwareTrustFact] = field(default_factory=list)
    coverage: CoverageReport = field(default_factory=CoverageReport)
    source_digests: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "collection_type": "OS_KERNEL_SNAPSHOT",
            "engine": COLLECTOR_NAME,
            "collector_version": COLLECTOR_VERSION,
            "host_id": self.host_id,
            "identity": self.identity.as_dict(),
            "crypto_api": [e.as_dict() for e in self.crypto_api],
            "crypto_api_notes": self.crypto_api_notes,
            "modules": [m.as_dict() for m in self.modules],
            "config_flags": self.config_flags,
            "storage": [s.as_dict() for s in self.storage],
            "hardware_trust": [h.as_dict() for h in self.hardware_trust],
            "coverage": self.coverage.as_dict(),
            "source_digests": self.source_digests,
            "note": "read-only snapshot collection (Tier 1, §11) — a "
                    "finding, never a verdict; runtime usage is never "
                    "confirmed by OS collection (§2.2)",
        }


def _read_source(name: str, path: Path,
                 coverage: CoverageReport,
                 digests: Dict[str, str],
                 reader: Optional[Callable[[str], object]] = None
                 ) -> Optional[str]:
    """Bounded read with honest degradation (§2.1)."""
    coverage.sources_attempted.append(name)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[
            :MAX_SOURCE_BYTES]
    except PermissionError:
        coverage.sources_unavailable.append(
            {"source": name, "reason": "permission_denied"})
        return None
    except (FileNotFoundError, IsADirectoryError, OSError) as exc:
        coverage.sources_unavailable.append(
            {"source": name,
             "reason": f"unavailable ({type(exc).__name__})"})
        return None
    coverage.sources_collected.append(name)
    digests[name] = evidence_digest(text)
    return text


def collect_linux(host_id: str,
                  source_root: str = "/",
                  collect_hardware_trust: bool = True) -> OSInventory:
    """Collect the Linux OS cryptographic inventory (§15 step 5).

    `source_root` is overridable for fixtures/tests; production runs
    read the live filesystem read-only."""
    root = Path(source_root)
    coverage = CoverageReport()
    digests: Dict[str, str] = {}
    captured: Dict[str, str] = {}

    # `uname -r` content or /proc/version or full `uname -a` line; the
    # parser accepts all three (identity.parse_uname_line).
    text = _read_source("uname", root / "proc/version", coverage, digests)
    if text is not None:
        captured["uname"] = text.strip()

    for name, path in (("os_release", root / "etc/os-release"),
                       ("cmdline", root / "proc/cmdline"),
                       ("tainted", root / "proc/sys/kernel/tainted")):
        t = _read_source(name, path, coverage, digests)
        if t is not None:
            captured[name] = t

    identity = collect_identity(captured)

    text = _read_source("proc_crypto", root / "proc/crypto", coverage,
                        digests)
    crypto_entries: List[CryptoApiEntry] = []
    crypto_notes: List[str] = []
    if text is not None:
        crypto_entries, crypto_notes = parse_crypto_api(text)

    text = _read_source("proc_modules", root / "proc/modules", coverage,
                        digests)
    modules = parse_modules(text) if text is not None else []
    if text is None:
        identity.notes.append("module list unavailable — LKM inventory "
                              "is UNKNOWN for this host, never 'no "
                              "modules' (§2.1)")

    text = _read_source("config_flags",
                        root / "proc/config.gz-or-boot-config",
                        coverage, digests)
    config_flags: Dict[str, str] = {}
    if text is not None:
        config_flags, _ = parse_config_flags(text)

    text = _read_source("storage_metadata", root / "proc/lsblk-f",
                        coverage, digests)
    storage = parse_lsblk(text) if text is not None else []

    hardware_trust: List[HardwareTrustFact] = []
    if collect_hardware_trust:
        # TPM: device presence via /dev (metadata only, no access to
        # sealed keys — §7).
        tpm_nodes = sorted(str(p) for p in Path("/dev").glob("tpm*")) \
            if root == Path("/") else []
        coverage.sources_attempted.append("tpm_device")
        if tpm_nodes:
            coverage.sources_collected.append("tpm_device")
            hardware_trust.append(HardwareTrustFact(
                subject="tpm", state="present",
                metadata={"device_nodes": tpm_nodes},
                notes=["TPM device node(s) present — device presence is "
                       "metadata, never a trust verdict (§12); no "
                       "sealed key material is accessed (§7)"]))
        else:
            coverage.sources_unavailable.append(
                {"source": "tpm_device",
                 "reason": "no /dev/tpm* nodes observed — presence "
                           "UNAVAILABLE from this source, never 'no TPM' "
                           "(§2.1)"})
            hardware_trust.append(HardwareTrustFact(
                subject="tpm", state="unavailable",
                evidence_class="unknown",
                notes=["no TPM device node observed in /dev — recorded "
                       "as unavailable; absence of a device node is not "
                       "proof of absence of a TPM (§2.1)"]))
        coverage.sources_attempted.append("random_device")
        if (Path("/dev/urandom").exists() and root == Path("/")):
            coverage.sources_collected.append("random_device")
            hardware_trust.append(HardwareTrustFact(
                subject="rng", state="present",
                metadata={"devices": "/dev/random, /dev/urandom"},
                notes=["random device nodes present — device presence "
                       "never means 'entropy is secure'; randomness "
                       "health needs corroboration from entropy sources "
                       "and their trust configuration (§5, OS-CRYPTO-"
                       "016)"]))

    return OSInventory(
        host_id=host_id,
        identity=identity,
        crypto_api=crypto_entries,
        crypto_api_notes=crypto_notes,
        modules=modules,
        config_flags=config_flags,
        storage=storage,
        hardware_trust=hardware_trust,
        coverage=coverage,
        source_digests=digests,
    )
