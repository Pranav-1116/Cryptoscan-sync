"""Windows OS & Kernel Intelligence collector
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §15 step 9).

Consumes captured Windows command/registry outputs and normalizes them
into the SAME canonical OSInventory model the Linux collector uses —
one canonical model, one evidence shape, per §15 step 4.

Sources (read-only, captured by an authorized collector):
  systeminfo / ver          — OS identity
  certutil -csplist         — CSP + KSP provider registrations (CNG)
  (certificate metadata is NOT collected in this build — OS-CRYPTO-008
   reports not_evaluable on every platform; a source list is a claim)
  reg query ...\\SCHANNEL    — TLS protocol configuration (the
                              enabled-by-config axis ONLY — supported
                              and observed-negotiated stay distinct and
                              are NOT established here, §9)
  reg query ...\\...\\00010002 — cipher suite ordering (configuration)
  manage-bde -status        — BitLocker METADATA (§7: never key
                              material, never recovery passwords)
  Get-Tpm                   — TPM presence/state metadata (never a
                              trust verdict, §12)
  Confirm-SecureBootUEFI    — Secure Boot state
  driverquery               — loaded drivers (the module inventory)

Discipline (§2.1): a failed or denied command is recorded as
'unavailable' or 'permission_denied' — never 'absent', never zeros.
Provider registrations are inventory — never proof of runtime use
(§2.2). ETW runtime tracing is Tier 2 and NOT implemented.

Provenance: the test fixtures are RECONSTRUCTED from documented output
formats, not captured from a live Windows host — a successful parse is
NOT Windows fleet qualification (§12).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .crypto_api import CryptoApiEntry
from .evidence import CoverageReport, evidence_digest
from .inventory import HardwareTrustFact, KernelModule, \
    StorageEncryptionFact
from .identity import OSIdentity

MAX_ENTRIES = 4096
MAX_LINE = 4096

SOURCES = (
    "systeminfo", "ver", "certutil_csplist",
    "reg_schannel_protocols", "reg_cipher_order", "manage_bde",
    "get_tpm", "confirm_secureboot", "driverquery",
)


def parse_systeminfo(text: str) -> Dict[str, str]:
    """Parse `systeminfo` key/value lines (bounded). Locale-dependent
    headers vary — unrecognized lines are skipped, never guessed."""
    fields: Dict[str, str] = {}
    for line in text.splitlines()[:200]:
        line = line[:MAX_LINE]
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            continue
        low = key.lower()
        if low.startswith("os name"):
            fields["os_pretty_name"] = value
        elif low.startswith("os version"):
            # "10.0.20348 N/A Build 20348"
            fields["os_version_raw"] = value
            m = re.search(r"(\d+\.\d+\.\d+)", value)
            if m:
                fields["kernel_release"] = m.group(1)
            m = re.search(r"Build\s+(\d+)", value, re.IGNORECASE)
            if m:
                fields["build"] = m.group(1)
        elif low.startswith("system type"):
            fields["machine"] = value.lower().replace(" ", "-")
    return fields


def parse_ver(text: str) -> str:
    """Parse `ver` output: 'Microsoft Windows [Version 10.0.20348.1]'."""
    m = re.search(r"\[Version\s+([0-9.]+)\]", text)
    return m.group(1) if m else ""


def parse_csplist(text: str) -> Tuple[List[CryptoApiEntry], List[str]]:
    """Parse `certutil -csplist` provider registrations.

    Each provider is a name line followed by 'Provider Type: N' and
    optional flags lines. CSPs and KSPs are both CRYPTO PROVIDERS —
    registered providers, never proof any application used them (§2.2).
    """
    entries: List[CryptoApiEntry] = []
    notes: List[str] = []
    current_name: Optional[str] = None
    current_fields: Dict[str, str] = {}

    def flush() -> None:
        nonlocal current_name, current_fields
        if current_name is None:
            if current_fields:
                if len(entries) < MAX_ENTRIES:
                    entry = CryptoApiEntry(
                        name="", driver="", type="unknown",
                        module="windows-crypto-api",
                        raw_fields=dict(current_fields),
                        parse_notes=[
                            "entry has neither name nor driver — "
                            "recorded as unidentified, never guessed"])
                    entries.append(entry)
                current_fields = {}
            return
        if len(entries) >= MAX_ENTRIES:
            current_name, current_fields = None, {}
            return
        kind = ("ksp" if "key storage provider" in current_name.lower()
                else "csp")
        entry = CryptoApiEntry(
            name=current_name,
            driver=current_name,
            type=kind,
            module="windows-crypto-api",
            raw_fields=dict(current_fields),
        )
        if "provider_type" in current_fields:
            try:
                entry.priority = int(current_fields["provider_type"])
            except ValueError:
                entry.parse_notes.append(
                    f"provider type {current_fields['provider_type']!r} "
                    "is not an integer — left unknown, never guessed")
        entry.parse_notes.append(
            "a registered Windows crypto provider (CSP/KSP) is "
            "inventory — never proof of runtime use (§2.2)")
        entries.append(entry)
        current_name, current_fields = None, {}

    for raw in text.splitlines()[:MAX_ENTRIES * 12]:
        line = raw.strip()[:MAX_LINE]
        if not line:
            continue
        low = line.lower()
        if low.startswith("provider type:"):
            value = line.partition(":")[2].strip()
            current_fields["provider_type"] = value
        elif low.startswith("encryption service provider:") or \
                low.startswith("key storage provider:"):
            flush()
            current_name = line.partition(":")[2].strip()
        elif ":" not in line and not low.startswith("provider"):
            # a bare name line starts a new provider block
            flush()
            current_name = line
        elif current_name is not None and ":" in line:
            key, _, value = line.partition(":")
            current_fields[key.strip().lower().replace(" ", "_")] = \
                value.strip()
    flush()
    return entries, notes


_REG_LINE = re.compile(
    r"^\s*(\S.*?)\s+(REG_(?:DWORD|QWORD|SZ|EXPAND_SZ|MULTI_SZ|BINARY))\s+"
    r"(.*)$")


def parse_reg_query(text: str) -> Tuple[Dict[str, str], List[str]]:
    """Parse `reg query` output into key/value states.

    'REG_DWORD 0x0' becomes '0x0'. A key with NO value line is
    'not_configured' — distinct from an explicit disabled value (§2.1):
    only what the source RECORDS is a recorded state."""
    flags: Dict[str, str] = {}
    notes: List[str] = []
    current_key = ""
    for raw in text.splitlines()[:4096]:
        line = raw.rstrip()[:MAX_LINE]
        if not line.strip():
            continue
        if not line[0].isspace() and re.match(r"^[A-Z_]+_LOCAL_MACHINE\\",
                                              line, re.IGNORECASE):
            current_key = line.strip()
            continue
        m = _REG_LINE.match(line)
        if m and current_key:
            name, regtype, value = m.groups()
            full = f"{current_key}\\{name.strip()}"
            flags[full] = value.strip()
        elif current_key and line.strip().lower().startswith("hkey"):
            current_key = line.strip()
    return flags, notes


def parse_schannel_protocols(reg: Dict[str, str]
                             ) -> Tuple[Dict[str, str], List[str]]:
    """Normalize SCHANNEL protocol registry values into configuration
    states. These are the ENABLED-BY-CONFIG axis only (§9): whether a
    protocol is SUPPORTED by the stack or OBSERVED negotiating is NOT
    established here."""
    flags: Dict[str, str] = {}
    for key, value in reg.items():
        if "\\protocols\\" not in key.lower():
            continue
        m = re.search(r"\\protocols\\([^\\]+)\\(client|server)\\"
                      r"(enabled|disabledbydefault)$", key,
                      re.IGNORECASE)
        if not m:
            continue
        protocol, side, setting = m.groups()
        side, setting = side.lower(), setting.lower()
        try:
            state = "enabled" if int(value, 0) else "disabled"
        except ValueError:
            state = f"unparsed({value})"
        flags[f"SCHANNEL\\{protocol}\\{side}\\{setting}"] = state
    return flags, []


def parse_manage_bde(text: str
                     ) -> Tuple[List[StorageEncryptionFact], List[str]]:
    """Parse `manage-bde -status` — BitLocker METADATA only (§7): no
    recovery passwords, no key protectors, no key material."""
    facts: List[StorageEncryptionFact] = []
    notes: List[str] = []
    current: Optional[StorageEncryptionFact] = None
    for raw in text.splitlines()[:400]:
        line = raw.strip()[:MAX_LINE]
        if not line:
            continue
        m = re.match(r"^Volume\s+([A-Za-z]:)\s+\[(.*)\]$", line)
        if m:
            current = StorageEncryptionFact(
                device=f"{m.group(1)} ({m.group(2)})")
            facts.append(current)
            continue
        if current is None:
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key in ("conversion status", "encryption method",
                       "protection status", "encryption percentage"):
                current.metadata[key.replace(" ", "_")] = value
    for fact in facts:
        method = fact.metadata.get("encryption_method", "")
        status = fact.metadata.get("conversion_status", "")
        if status.lower() == "fully encrypted":
            fact.notes.append(
                "BitLocker conversion status observed as fully "
                "encrypted — metadata only; no recovery password or "
                "key protector is collected (§7)")
        elif status:
            fact.notes.append(
                f"BitLocker conversion status {status!r} — 'not fully "
                "encrypted' is the recorded state, never a security "
                "verdict; no key material is collected (§7)")
    return facts, notes


def parse_get_tpm(text: str
                  ) -> Tuple[Optional[HardwareTrustFact], List[str]]:
    """Parse `Get-Tpm` output. An error/empty output is UNAVAILABLE —
    never 'no TPM' (§2.1). Presence is metadata, never a trust verdict
    (§12)."""
    notes: List[str] = []
    stripped = text.strip()
    if not stripped or "Get-Tpm" in stripped and ":" not in stripped:
        return None, notes
    low_all = stripped.lower()
    if any(marker in low_all for marker in
           ("access is denied", "exception", "0x8007", "not recognized",
            "cannot be", "cmdlet")):
        # a failed/denied command is UNAVAILABLE — never 'no TPM' (§2.1)
        return None, notes
    fields: Dict[str, str] = {}
    for line in stripped.splitlines()[:40]:
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip().lower().replace(" ", "_")] = v.strip()
    if "tpmpresent" not in fields:
        # no parseable TPM state — unavailable, never guessed
        return None, notes
    present = fields.get("tpmpresent", "").lower()
    ready = fields.get("tpmready", "").lower()
    state = "present" if present == "true" else (
        "unavailable" if present == "false" else "unknown")
    fact = HardwareTrustFact(
        subject="tpm", state=state,
        evidence_class="observed" if state == "present" else "unknown",
        metadata={k: v for k, v in fields.items()
                  if k in ("tpmpresent", "tpmready", "tpmmanaged",
                           "manufactureridtxt", "manufacturerversion")},
        notes=["TPM state is collected metadata — presence and "
               "readiness are never a trust verdict (§12); no sealed "
               "key material is accessed (§7)"])
    return fact, notes


def parse_secureboot(text: str
                     ) -> Optional[HardwareTrustFact]:
    """Parse `Confirm-SecureBootUEFI` output ('True'/'False'). An error
    message is UNAVAILABLE — never 'disabled' (§2.1)."""
    stripped = text.strip()
    if stripped.lower() == "true":
        return HardwareTrustFact(
            subject="secure_boot", state="enabled",
            evidence_class="observed",
            notes=["Secure Boot state read via Confirm-SecureBootUEFI — "
                   "a configuration state, never a boot-integrity "
                   "verdict"])
    if stripped.lower() == "false":
        return HardwareTrustFact(
            subject="secure_boot", state="disabled",
            evidence_class="observed",
            notes=["Secure Boot reported disabled by the firmware "
                   "interface — a configuration state; OS-CRYPTO-010 "
                   "detects from this, it does not judge the host"])
    return HardwareTrustFact(
        subject="secure_boot", state="unavailable",
        evidence_class="unknown",
        notes=["Secure Boot state unavailable from this source — "
               "recorded as unavailable, NEVER as 'disabled' (§2.1)"])


def parse_driverquery(text: str) -> List[KernelModule]:
    """Parse `driverquery /fo list` — the Windows module inventory.
    A row without a module name is skipped, never fabricated."""
    modules: List[KernelModule] = []
    name = ""
    for raw in text.splitlines()[:4096]:
        line = raw.strip()[:MAX_LINE]
        if not line:
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key in ("module name", "modulename"):
                name = value
                if name:
                    modules.append(KernelModule(name=name))
            elif key in ("state", "status") and modules:
                modules[-1].state = value
            elif key in ("display name", "driver type") and modules:
                modules[-1].notes.append(f"{key}: {value}")
        if len(modules) >= MAX_ENTRIES:
            break
    return modules


def collect_windows(host_id: str, captured: Dict[str, str]
                    ) -> Dict[str, Any]:
    """Normalize captured Windows outputs into the ONE canonical
    OSInventory shape (the same dict the Linux collector produces and
    the same rows os_assets…os_coverage persist).

    Missing captures are UNAVAILABLE sources (§2.1) — never 'absent',
    never zeros. `captured` keys are the source names in SOURCES; a
    source may also be given as a dict {"error": ...} to record a
    denied/failed command explicitly.
    """
    coverage = CoverageReport()
    digests: Dict[str, str] = {}
    notes: List[str] = []

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

    # --- identity ----------------------------------------------------
    identity = OSIdentity()
    identity.kernel_name = "Windows_NT"
    identity.notes.append(
        "platform: windows — collection normalized into the shared "
        "canonical OS model (§15 step 4); Linux-only rule inputs are "
        "reported not_evaluable, never as clean")
    sysinfo = source("systeminfo")
    fields = parse_systeminfo(sysinfo) if sysinfo else {}
    identity.os_pretty_name = fields.get("os_pretty_name", "")
    identity.kernel_release = fields.get("kernel_release", "")
    identity.kernel_version = fields.get("os_version_raw", "")
    identity.machine = fields.get("machine", "")
    ver_text = source("ver")
    if ver_text:
        ver_release = parse_ver(ver_text)
        if ver_release and not identity.kernel_release:
            identity.kernel_release = ver_release
    if not identity.kernel_release:
        identity.notes.append(
            "OS build unavailable — kernel release recorded as "
            "unknown, never guessed (§2.1)")
    identity_data = identity.as_dict()
    identity_data["platform"] = "windows"
    identity_data["build"] = fields.get("build", "unknown")

    # --- crypto providers (CSP/KSP registrations) --------------------
    csplist = source("certutil_csplist")
    crypto_entries: List[Dict[str, Any]] = []
    crypto_notes: List[str] = []
    if csplist is not None:
        entries, pnotes = parse_csplist(csplist)
        crypto_notes.extend(pnotes)
        for e in entries:
            d = e.as_dict()
            d["note"] = ("registered Windows crypto provider (CSP/KSP) "
                         "— inventory, never proof of runtime use "
                         "(§2.2); a registered provider is not a claim "
                         "about any application")
            crypto_entries.append(d)

    # --- configuration (SCHANNEL protocols + cipher order) -----------
    config_flags: Dict[str, str] = {}
    channel_reg = source("reg_schannel_protocols")
    if channel_reg is not None:
        reg, _ = parse_reg_query(channel_reg)
        flags, _ = parse_schannel_protocols(reg)
        config_flags.update(flags)
        config_flags["__tls_axis__"] = (
            "these are ENABLED-BY-CONFIG states only — supported and "
            "observed-negotiated are distinct TLS findings and are NOT "
            "established by this source (§9)")
    order_reg = source("reg_cipher_order")
    if order_reg is not None:
        reg, _ = parse_reg_query(order_reg)
        for key, value in reg.items():
            if key.lower().endswith("functions"):
                config_flags["CIPHER_ORDER\\functions"] = value[:200]

    # --- storage (BitLocker metadata) --------------------------------
    bde = source("manage_bde")
    storage: List[Dict[str, Any]] = []
    if bde is not None:
        facts, _ = parse_manage_bde(bde)
        storage = [f.as_dict() for f in facts]

    # --- hardware trust ----------------------------------------------
    hardware_trust: List[Dict[str, Any]] = []
    tpm_text = source("get_tpm")
    if tpm_text is None:
        # denied or failed source: an explicit UNAVAILABLE fact — the
        # availability of a TPM is not established, never 'no TPM'
        hardware_trust.append(HardwareTrustFact(
            subject="tpm", state="unavailable",
            evidence_class="unknown",
            notes=["the TPM state source was unavailable or "
                   "permission-denied — recorded as unavailable, never "
                   "as 'no TPM' (§2.1)"]).as_dict())
    if tpm_text is not None:
        fact, _ = parse_get_tpm(tpm_text)
        if fact is not None:
            hardware_trust.append(fact.as_dict())
        else:
            hardware_trust.append(HardwareTrustFact(
                subject="tpm", state="unavailable",
                evidence_class="unknown",
                notes=["Get-Tpm returned no parseable state — recorded "
                       "as unavailable, never as 'no TPM' (§2.1)"]
            ).as_dict())
    sb_text = source("confirm_secureboot")
    if sb_text is None:
        hardware_trust.append(HardwareTrustFact(
            subject="secure_boot", state="unavailable",
            evidence_class="unknown",
            notes=["the Secure Boot state source was unavailable or "
                   "permission-denied — recorded as unavailable, NEVER "
                   "as 'disabled' (§2.1)"]).as_dict())
    if sb_text is not None:
        fact = parse_secureboot(sb_text)
        if fact is not None:
            hardware_trust.append(fact.as_dict())

    # --- modules (loaded drivers) ------------------------------------
    drivers = source("driverquery")
    modules = [m.as_dict() for m in parse_driverquery(drivers)] \
        if drivers is not None else []
    if drivers is None:
        identity.notes.append(
            "driver inventory unavailable — module list UNKNOWN for "
            "this host, never 'no drivers' (§2.1)")

    return {
        "collection_type": "OS_KERNEL_SNAPSHOT",
        "engine": "cryptoscan-os-intelligence",
        "collector_version": "os-intelligence/1.0.0",
        "host_id": host_id,
        "identity": identity_data,
        "crypto_api": crypto_entries,
        "crypto_api_notes": crypto_notes,
        "modules": modules,
        "config_flags": config_flags,
        "storage": storage,
        "hardware_trust": hardware_trust,
        "coverage": coverage.as_dict(),
        "source_digests": digests,
        "note": ("Windows read-only collection normalized into the "
                 "canonical OS model (§15 step 4) — registrations and "
                 "metadata, never proof of runtime use (§2.2); ETW "
                 "runtime tracing is Tier 2 and NOT implemented"),
    }
