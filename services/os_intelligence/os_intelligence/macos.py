"""macOS OS & Kernel Intelligence collector
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §15 step 9).

Consumes captured macOS command outputs and normalizes them into the
SAME canonical OSInventory model as the Linux and Windows collectors
(§15 step 4).

Sources (read-only, captured by an authorized collector):
  sw_vers                  — OS identity (ProductName, ProductVersion,
                             BuildVersion)
  uname -r / sysctl        — kernel release + machine
  csrutil status           — System Integrity Protection state
  spctl --status           — Gatekeeper state
  fdesetup status          — FileVault disk-encryption METADATA (§7:
                             never recovery keys, never passwords)
  kmutil showloaded        — loaded kernel extensions (module
                             inventory) / kextstat fallback

Discipline (§2.1): a failed or denied command is recorded as
'unavailable' or 'permission_denied' — never 'absent', never zeros.

The spec boundary (§5/§7): macOS collection uses Security framework /
Keychain APIs and command-line tool OUTPUT — protected storage files
are NEVER scraped. This build reads only the command outputs listed
above; it does not open keychain databases or protected plists.

macOS exposes no kernel-crypto registration inventory equivalent to
/proc/crypto: the crypto provider inventory is UNAVAILABLE from these
read-only sources — recorded as unavailable, never 'no providers'.

Provenance: the test fixtures are RECONSTRUCTED from documented
output formats, not captured from a live macOS host — a successful
parse is NOT macOS fleet qualification (§12).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .evidence import CoverageReport, evidence_digest
from .identity import OSIdentity
from .inventory import HardwareTrustFact, KernelModule, \
    StorageEncryptionFact

MAX_ENTRIES = 2048
MAX_LINE = 4096

SOURCES = (
    "sw_vers", "uname", "csrutil", "spctl", "fdesetup", "kmutil",
    "certificate_metadata",
)


def parse_sw_vers(text: str) -> Dict[str, str]:
    """Parse `sw_vers` output:
    ProductName:    macOS
    ProductVersion: 14.6.1
    BuildVersion:   23G93
    """
    fields: Dict[str, str] = {}
    for line in text.splitlines()[:40]:
        line = line[:MAX_LINE]
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        low = key.lower()
        if low == "productname":
            fields["os_pretty_name"] = value
        elif low == "productversion":
            fields["os_version_id"] = value
        elif low == "buildversion":
            fields["build"] = value
    return fields


def parse_uname(text: str) -> Dict[str, str]:
    """Parse `uname -r` / `uname -m` style output."""
    result: Dict[str, str] = {}
    for line in text.splitlines()[:8]:
        line = line.strip()
        if not line:
            continue
        # a bare release like "23.6.0" or "x86_64"/"arm64"
        if re.fullmatch(r"\d+(\.\d+)*", line):
            result["kernel_release"] = line
        elif line in ("x86_64", "arm64", "arm64e", "i386"):
            result["machine"] = line
    return result


def parse_csrutil(text: str) -> Optional[HardwareTrustFact]:
    """Parse `csrutil status`:
    'System Integrity Protection status: enabled.' / 'disabled.'
    An unrecognized or error output is UNAVAILABLE — never 'disabled'
    (§2.1). SIP state is a configuration state, never a trust verdict."""
    stripped = text.strip()
    m = re.search(r"status:\s*(enabled|disabled)", stripped,
                  re.IGNORECASE)
    if not m:
        return HardwareTrustFact(
            subject="sip", state="unavailable",
            evidence_class="unknown",
            notes=["SIP state unavailable from this source — recorded "
                   "as unavailable, NEVER as 'disabled' (§2.1)"])
    state = m.group(1).lower()
    return HardwareTrustFact(
        subject="sip", state=state,
        evidence_class="observed",
        notes=["System Integrity Protection state read via csrutil — "
               "a configuration state, never a trust verdict (§12)"])


def parse_spctl(text: str) -> Optional[HardwareTrustFact]:
    """Parse `spctl --status`: 'assessments enabled' / 'assessments
    disabled'. Error output is UNAVAILABLE — never 'disabled'."""
    stripped = text.strip().lower()
    if "enabled" in stripped:
        state = "enabled"
    elif "disabled" in stripped:
        state = "disabled"
    else:
        return HardwareTrustFact(
            subject="gatekeeper", state="unavailable",
            evidence_class="unknown",
            notes=["Gatekeeper state unavailable from this source — "
                   "recorded as unavailable, NEVER as 'disabled' "
                   "(§2.1)"])
    return HardwareTrustFact(
        subject="gatekeeper", state=state,
        evidence_class="observed",
        notes=["Gatekeeper assessment state read via spctl — a "
               "configuration state, never a trust verdict (§12)"])


def parse_fdesetup(text: str
                   ) -> Tuple[Optional[StorageEncryptionFact],
                              List[str]]:
    """Parse `fdesetup status`:
    'FileVault is On.' / 'FileVault is Off.'
    METADATA only (§7): no recovery keys, no passwords, no key
    material — and 'Off' is the recorded state, never a verdict."""
    stripped = text.strip()
    notes: List[str] = []
    if re.search(r"filevault is on", stripped, re.IGNORECASE):
        fact = StorageEncryptionFact(
            device="boot volume",
            fstype="FileVault",
            metadata={"conversion_status": "Fully Encrypted",
                      "encryption_layer": "FileVault"})
        fact.notes.append(
            "FileVault state observed as On — metadata only; no "
            "recovery key or password is collected (§7)")
        return fact, notes
    if re.search(r"filevault is off", stripped, re.IGNORECASE):
        fact = StorageEncryptionFact(
            device="boot volume",
            fstype="FileVault",
            metadata={"conversion_status": "Fully Decrypted",
                      "encryption_layer": "FileVault"})
        fact.notes.append(
            "FileVault state observed as Off — the recorded state, "
            "never a security verdict; no key material is collected "
            "(§7)")
        return fact, notes
    return None, notes


def parse_kmutil(text: str) -> List[KernelModule]:
    """Parse `kmutil showloaded` / `kextstat` bundle rows. A row
    without an identifier is skipped, never fabricated."""
    modules: List[KernelModule] = []
    for raw in text.splitlines()[:MAX_ENTRIES * 4]:
        line = raw.strip()[:MAX_LINE]
        if not line:
            continue
        # kextstat-style: Index Refs Address Size Wired Name (Version)
        m = re.match(r"^\d+\s+\d+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+"
                     r"0x[0-9a-fA-F]+\s+(\S+)\s+\(([^)]*)\)", line)
        if m:
            modules.append(KernelModule(
                name=m.group(1), state="loaded",
                notes=[f"version: {m.group(2)}"]))
            continue
        # kmutil showloaded-style: bundle id lines
        m2 = re.match(r"^([a-zA-Z0-9_.-]+\.[a-zA-Z0-9_.-]+)\s+\("
                      r"([^)]*)\)", line)
        if m2:
            modules.append(KernelModule(
                name=m2.group(1), state="loaded",
                notes=[f"version: {m2.group(2)}"]))
        if len(modules) >= MAX_ENTRIES:
            break
    return modules


def collect_macos(host_id: str, captured: Dict[str, str]
                  ) -> Dict[str, Any]:
    """Normalize captured macOS outputs into the ONE canonical
    OSInventory shape. Missing captures are UNAVAILABLE sources (§2.1).
    `captured` values may be dicts {"error": ...} to record a denied
    command explicitly."""
    coverage = CoverageReport()
    digests: Dict[str, str] = {}

    def source(name: str) -> Optional[str]:
        coverage.sources_attempted.append(name)
        value = captured.get(name)
        if value is None:
            coverage.sources_unavailable.append(
                {"source": name,
                 "reason": "unavailable (not provided to the "
                           "collector)"})
            return None
        if isinstance(value, dict):
            coverage.sources_unavailable.append(
                {"source": name,
                 "reason": str(value.get("error",
                                         "permission_denied"))[:200]})
            return None
        text = str(value)
        coverage.sources_collected.append(name)
        digests[name] = evidence_digest(text)
        return text

    identity = OSIdentity()
    identity.notes.append(
        "platform: macos — collection normalized into the shared "
        "canonical OS model (§15 step 4); Linux-only rule inputs are "
        "reported not_evaluable, never as clean")
    identity.notes.append(
        "collection boundary (§5/§7): Security framework / Keychain "
        "command OUTPUTS only — protected storage files and keychain "
        "databases are never scraped")

    sw_text = source("sw_vers")
    fields = parse_sw_vers(sw_text) if sw_text else {}
    identity.os_pretty_name = fields.get("os_pretty_name", "")
    identity.os_version_id = fields.get("os_version_id", "")
    uname_text = source("uname")
    uname_fields = parse_uname(uname_text) if uname_text else {}
    identity.kernel_release = uname_fields.get("kernel_release", "")
    identity.kernel_name = "Darwin"
    identity.machine = uname_fields.get("machine", "")
    identity.kernel_version = fields.get("build", "")
    if not identity.kernel_release:
        identity.notes.append(
            "kernel release unavailable — recorded as unknown, never "
            "guessed (§2.1)")

    identity_data = identity.as_dict()
    identity_data["platform"] = "macos"
    identity_data["build"] = fields.get("build", "unknown")

    # crypto provider inventory: NO read-only equivalent exists
    coverage.sources_attempted.append("crypto_provider_inventory")
    coverage.sources_unavailable.append({
        "source": "crypto_provider_inventory",
        "reason": "unavailable — macOS exposes no kernel-crypto "
                  "registration inventory equivalent to /proc/crypto "
                  "through read-only sources; recorded as unavailable, "
                  "NEVER as 'no providers' (§2.1)"})
    crypto_notes = [
        "macOS crypto provider inventory is unavailable from read-only "
        "sources — never 'no providers', never 'no cryptography' (§2.1)"]

    config_flags: Dict[str, str] = {}

    # storage: FileVault METADATA
    fde_text = source("fdesetup")
    storage: List[Dict[str, Any]] = []
    if fde_text is not None:
        fact, _ = parse_fdesetup(fde_text)
        if fact is not None:
            storage.append(fact.as_dict())
        else:
            storage.append(StorageEncryptionFact(
                device="boot volume", fstype="FileVault",
                metadata={"conversion_status": "unknown"},
                notes=["fdesetup output unparseable — FileVault state "
                       "UNKNOWN, never guessed (§2.1)"]).as_dict())

    # hardware trust: SIP + Gatekeeper
    hardware_trust: List[Dict[str, Any]] = []
    csr_text = source("csrutil")
    if csr_text is not None:
        fact = parse_csrutil(csr_text)
        if fact is not None:
            hardware_trust.append(fact.as_dict())
    else:
        hardware_trust.append(HardwareTrustFact(
            subject="sip", state="unavailable",
            evidence_class="unknown",
            notes=["the SIP state source was unavailable or "
                   "permission-denied — recorded as unavailable, NEVER "
                   "as 'disabled' (§2.1)"]).as_dict())
    spctl_text = source("spctl")
    if spctl_text is not None:
        fact = parse_spctl(spctl_text)
        if fact is not None:
            hardware_trust.append(fact.as_dict())
    else:
        hardware_trust.append(HardwareTrustFact(
            subject="gatekeeper", state="unavailable",
            evidence_class="unknown",
            notes=["the Gatekeeper state source was unavailable or "
                   "permission-denied — recorded as unavailable, NEVER "
                   "as 'disabled' (§2.1)"]).as_dict())

    # certificates (public metadata only — §7)
    from .certificates import build_certificates
    certificates: List[Dict[str, Any]] = []
    cert_text = source("certificate_metadata")
    if cert_text is not None:
        certificates = build_certificates("certificate_metadata",
                                          cert_text)

    # modules: kernel extensions
    kext_text = source("kmutil")
    modules = [m.as_dict() for m in parse_kmutil(kext_text)] \
        if kext_text is not None else []
    if kext_text is None:
        identity.notes.append(
            "kernel extension inventory unavailable — module list "
            "UNKNOWN for this host, never 'no modules' (§2.1)")

    return {
        "collection_type": "OS_KERNEL_SNAPSHOT",
        "engine": "cryptoscan-os-intelligence",
        "collector_version": "os-intelligence/1.0.0",
        "host_id": host_id,
        "identity": identity_data,
        "crypto_api": [],
        "crypto_api_notes": crypto_notes,
        "modules": modules,
        "config_flags": config_flags,
        "storage": storage,
        "hardware_trust": hardware_trust,
        "certificates": certificates,
        "coverage": coverage.as_dict(),
        "source_digests": digests,
        "note": ("macOS read-only collection normalized into the "
                 "canonical OS model (§15 step 4) — Security framework "
                 "/ Keychain command outputs only; protected storage "
                 "files are never scraped; metadata, never proof of "
                 "runtime use (§2.2)"),
    }
