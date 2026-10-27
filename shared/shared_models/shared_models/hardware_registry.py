"""Hardware security registry — every crypto-relevant hardware device/feature
the scanner can identify, with its category, security verdict and a
deterministic risk/attestation assessment.

The network analogue of :mod:`algorithm_registry` / :mod:`network_registry`:
it turns a raw vendor/model/firmware/feature string observed by the hardware
scanner (public metadata only — never keys, PINs or endorsement secrets) into
a canonical, classified record:

    ("tpm", "2.0")           -> TPM 2.0        root-of-trust, REQUIRED
    ("tpm", "1.2")           -> TPM 1.2        root-of-trust, DEPRECATED
    ("hsm", "Luna")          -> Thales Luna HSM hardware-keystore, ALLOWED
    ("secure_element", "YubiKey 5") -> YubiKey 5 secure-element, ALLOWED
    ("tee", "SGX")           -> Intel SGX      trusted-execution, RESTRICTED
    ("sed", "Opal 2.0")      -> Opal self-encrypting drive, ALLOWED

Every lookup returns :class:`HardwareInfo`. Unknown devices degrade to
``status="UNKNOWN"`` — never silently treated as present/secure. Classification
is metadata-only and passive; it never causes a probe or touches secrets.


Vendor PQC data refreshed 2026-09 against SHIPPING support: Thales Luna fw 7.9
(ML-KEM/ML-DSA core), Entrust nShield fw 13.8.0 (CAVP-validated ML-KEM/ML-DSA/
SLH-DSA), Utimaco Se Gen2 fw 5.5 (validated ML-DSA-65 module), AWS/IBM/Google
cloud HSMs via managed firmware. quantum_resistant is set only for shipping
support; pilots/previews stay False and say so in notes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------- #
# verdicts
# --------------------------------------------------------------------------- #
REQUIRED = "REQUIRED"     # expected baseline root of trust (TPM 2.0 on modern assets)
ALLOWED = "ALLOWED"       # current, sound
RESTRICTED = "RESTRICTED" # usable with caveats / limited assurance
DEPRECATED = "DEPRECATED" # obsolete / weak — migrate
DISALLOWED = "DISALLOWED" # broken/known-vulnerable — do not rely on it
UNKNOWN = "UNKNOWN"       # unrecognized — human review

# device classes
ROOT_OF_TRUST = "root-of-trust"
HARDWARE_KEYSTORE = "hardware-keystore"
SECURE_ELEMENT = "secure-element"
SMART_CARD = "smart-card"
CRYPTO_ACCELERATOR = "crypto-accelerator"
TRUSTED_EXECUTION = "trusted-execution"
SELF_ENCRYPTING_DRIVE = "self-encrypting-drive"
MANAGEMENT_CONTROLLER = "management-controller"
HARDWARE_RNG = "hardware-rng"
SECURE_ENCLAVE = "secure-enclave"


@dataclass(frozen=True)
class _Hw:
    canonical: str
    category: str
    status: str
    manufacturer: str = ""
    aliases: tuple[str, ...] = ()
    quantum_resistant: bool = False
    attestation: bool = False      # supports remote/measured attestation
    notes: str = ""


_DEVICES: dict[str, _Hw] = {}
_BY_ALIAS: dict[str, _Hw] = {}


def _nk(name: str) -> str:
    return "".join(ch for ch in str(name).upper() if ch.isalnum())


def _add(
    canonical: str,
    category: str,
    status: str,
    *,
    manufacturer: str = "",
    aliases: tuple[str, ...] = (),
    quantum_resistant: bool = False,
    attestation: bool = False,
    notes: str = "",
) -> _Hw:
    d = _Hw(canonical, category, status, manufacturer=manufacturer, aliases=aliases,
            quantum_resistant=quantum_resistant, attestation=attestation, notes=notes)
    _DEVICES[_nk(canonical)] = d
    for a in aliases:
        _BY_ALIAS.setdefault(_nk(a), d)
    _BY_ALIAS.setdefault(_nk(canonical), d)
    return d


# -- TPM (Trusted Platform Module) — root of trust for measured boot -------- #
_add("TPM 2.0", ROOT_OF_TRUST, REQUIRED, manufacturer="TCG",
     aliases=("tpm2", "tpm20", "tpm-2.0", "tpm 2", "ftpm", "ptt", "dTPM 2.0", "fTPM 2.0"),
     attestation=True, quantum_resistant=False,
     notes="TCG TPM 2.0; measured boot + remote attestation; discrete (dTPM) preferred over firmware (fTPM/PTT)"),
_add("TPM 1.2", ROOT_OF_TRUST, DEPRECATED, manufacturer="TCG",
     aliases=("tpm12", "tpm1.2", "tpm-1.2", "tpm 1"),
     attestation=True, notes="TPM 1.2; weak crypto (SHA-1/RSA-1024), no ECC in many; replace/upgrade"),
_add("Trusted Platform Module", ROOT_OF_TRUST, UNKNOWN, manufacturer="TCG",
     aliases=("tpm",), notes="TPM of unspecified version — determine 1.2 vs 2.0"),

# -- HSMs (Hardware Security Modules) -------------------------------------- #
_add("Thales Luna HSM", HARDWARE_KEYSTORE, ALLOWED, manufacturer="Thales",
     aliases=("luna", "luna sa", "lunasa", "thales luna", "safenet luna", "gemalto luna"),
     attestation=True, quantum_resistant=True,
     notes="fw 7.9+ ships ML-KEM/ML-DSA in core firmware (Jul 2025); T-Series holds "
           "full CNSA 2.0 set (ML-DSA, ML-KEM, LMS) inside FIPS 140-3 L3 cert 5450"),
_add("Thales payShield", HARDWARE_KEYSTORE, ALLOWED, manufacturer="Thales",
     aliases=("payshield", "pay shield", "thales payshield"),
     notes="payment HSM (PIN/key management); vendor PQC roadmap announced — not yet "
           "in shipping firmware as of 2026-09, flag stays False until it ships"),
_add("Entrust nShield HSM", HARDWARE_KEYSTORE, ALLOWED, manufacturer="Entrust",
     aliases=("nshield", "nshield connect", "entrust nshield", "nfast"),
     attestation=True, quantum_resistant=True,
     notes="fw 13.8.0+ carries CAVP-validated ML-KEM, ML-DSA and SLH-DSA (Aug 2025); "
           "check module-level FIPS 140-3 cert before high-assurance procurement"),
_add("Utimaco SecurityServer", HARDWARE_KEYSTORE, ALLOWED, manufacturer="Utimaco",
     aliases=("utimaco", "securityserver", "utimaco hsm", "crypto server"),
     attestation=True, quantum_resistant=True,
     notes="Se Gen2 fw 5.5 module validated covering ML-DSA-65; ML-KEM/ML-DSA via PKCS#11"),
_add("AWS CloudHSM", HARDWARE_KEYSTORE, ALLOWED, manufacturer="AWS",
     aliases=("cloudhsm", "aws cloudhsm", "aws hsm"),
     attestation=True, quantum_resistant=True,
     notes="managed firmware ML-KEM/ML-DSA; AWS KMS internal HSM holds CMVP "
           "validation covering ML-DSA-65"),
_add("IBM Cloud HSM", HARDWARE_KEYSTORE, ALLOWED, manufacturer="IBM",
     aliases=("ibm hsm", "ibm cloud hsm"), quantum_resistant=True,
     notes="Crypto Express base (PQC-capable per IBM Z family); managed firmware rollout"),
_add("Google Cloud HSM", HARDWARE_KEYSTORE, ALLOWED, manufacturer="Google",
     aliases=("gcp hsm", "google hsm", "cloud hsm google"), quantum_resistant=True,
     notes="managed firmware PQC per vendor docs; verify module cert per region"),
_add("Azure Dedicated HSM", HARDWARE_KEYSTORE, ALLOWED, manufacturer="Microsoft",
     aliases=("azure hsm", "azure dedicated hsm"), quantum_resistant=True,
     notes="user-managed Thales Luna 7 — PQC requires YOUR firmware upgrade to 7.9+"),
_add("SoftHSM", HARDWARE_KEYSTORE, RESTRICTED, manufacturer="OpenDNSSEC",
     aliases=("softhsm", "softhsm2", "software hsm"),
     notes="software PKCS#11 token — NOT hardware; no hardware root of trust"),

# -- Secure elements / hardware tokens (USB, eSIM, embedded) --------------- #
_add("YubiKey 5", SECURE_ELEMENT, ALLOWED, manufacturer="Yubico",
     aliases=("yubikey", "yubikey 5", "yubikey5", "yubico"),
     attestation=True, notes="Yubico YubiKey 5 series (FIDO2/PIV/OpenPGP/OTP)"),
_add("YubiKey FIPS", SECURE_ELEMENT, ALLOWED, manufacturer="Yubico",
     aliases=("yubikey fips", "yubikey fips 4"),
     attestation=True, notes="FIPS 140-2 validated YubiKey"),
_add("YubiKey Security Key", SECURE_ELEMENT, ALLOWED, manufacturer="Yubico",
     aliases=("security key", "yubico security key", "security key by yubico"),
     attestation=True, notes="FIDO2/WebAuthn security key"),
_add("Google Titan Key", SECURE_ELEMENT, ALLOWED, manufacturer="Google",
     aliases=("titan", "titan key", "google titan", "titan security key"),
     attestation=True, notes="Google Titan FIDO security key"),
_add("SoloKeys", SECURE_ELEMENT, ALLOWED, manufacturer="SoloKeys",
     aliases=("solokey", "solokeys", "solo key"),
     attestation=True, notes="open-source FIDO2 key"),
_add("Ledger Hardware Wallet", SECURE_ELEMENT, RESTRICTED, manufacturer="Ledger",
     aliases=("ledger", "ledger nano", "nano s", "nano x"),
     notes="crypto-asset hardware wallet"),
_add("Trezor Hardware Wallet", SECURE_ELEMENT, RESTRICTED, manufacturer="Trezor",
     aliases=("trezor", "trezor model", "trezor one", "trezor t"),
     notes="crypto-asset hardware wallet"),
_add("Smart Card", SMART_CARD, RESTRICTED,
     aliases=("smartcard", "smart card", "piv card", "cac card", "javacard"),
     attestation=True, notes="PIV/CAC/JavaCard smart card (reader-dependent)"),
_add("eSIM/iSIM", SECURE_ELEMENT, RESTRICTED,
     aliases=("esim", "isim", "euicc"),
     notes="embedded/integregated SIM secure element"),

# -- Mobile / SoC secure enclaves ----------------------------------------- #
_add("Apple Secure Enclave", SECURE_ENCLAVE, ALLOWED, manufacturer="Apple",
     aliases=("secure enclave", "sep", "apple sep", "secure enclave processor"),
     attestation=True, notes="Apple Secure Enclave Processor (SEP)"),
_add("Android StrongBox", SECURE_ENCLAVE, ALLOWED, manufacturer="Google/Android",
     aliases=("strongbox", "android strongbox", "keymint strongbox"),
     attestation=True, notes="Android StrongBox Keymaster/KeyMint (TEE-backed)"),
_add("Android Keystore (TEE)", SECURE_ENCLAVE, RESTRICTED, manufacturer="Google/Android",
     aliases=("android keystore", "keymaster", "keymint", "tee keystore"),
     attestation=True, notes="Android hardware-backed keystore (TEE; StrongBox preferred)"),
_add("Samsung Knox TEE", SECURE_ENCLAVE, ALLOWED, manufacturer="Samsung",
     aliases=("knox", "samsung knox", "timobex", "teegris"),
     attestation=True, notes="Samsung Knox / TEEgrIS trusted environment"),
_add("Huawei iTrustee", SECURE_ENCLAVE, RESTRICTED, manufacturer="Huawei",
     aliases=("itrustee", "huawei tee", "trustzone huawei"),
     notes="Huawei TrustZone TEE"),
_add("Qualcomm QSEE", SECURE_ENCLAVE, RESTRICTED, manufacturer="Qualcomm",
     aliases=("qsee", "qtee", "qualcomm tee", "trustzone qsee"),
     notes="Qualcomm Secure Execution Environment (TrustZone)"),

# -- Trusted Execution Environments (CPU) ---------------------------------- #
_add("Intel SGX", TRUSTED_EXECUTION, RESTRICTED, manufacturer="Intel",
     aliases=("sgx", "intel sgx", "software guard extensions"),
     attestation=True, notes="Intel SGX enclaves; deprecated on many client CPUs, limited memory"),
_add("Intel TDX", TRUSTED_EXECUTION, ALLOWED, manufacturer="Intel",
     aliases=("tdx", "intel tdx", "trust domain extensions"),
     attestation=True, notes="Intel TDX confidential VMs"),
_add("AMD SEV-SNP", TRUSTED_EXECUTION, ALLOWED, manufacturer="AMD",
     aliases=("sev-snp", "sevsnp", "amd sev-snp", "snp"),
     attestation=True, notes="AMD SEV-SNP confidential VMs"),
_add("AMD SEV/SEV-ES", TRUSTED_EXECUTION, RESTRICTED, manufacturer="AMD",
     aliases=("sev", "sev-es", "seves", "amd sev"),
     attestation=True, notes="AMD SEV/SEV-ES; SEV-SNP preferred for stronger attestation"),
_add("ARM TrustZone", TRUSTED_EXECUTION, RESTRICTED, manufacturer="ARM",
     aliases=("trustzone", "arm trustzone", "tz", "el3"),
     attestation=True, notes="ARM TrustZone (normal/secure world)"),
_add("ARM CCA / Realm", TRUSTED_EXECUTION, ALLOWED, manufacturer="ARM",
     aliases=("cca", "arm cca", "realm management extension", "rme"),
     attestation=True, quantum_resistant=True, notes="ARM Confidential Compute Architecture (Realms)"),
_add("IBM Secure Execution", TRUSTED_EXECUTION, ALLOWED, manufacturer="IBM",
     aliases=("ibm secure execution", "secure execution", "s390x pv", "ibm z pv"),
     attestation=True, notes="IBM Z / LinuxONE Protected Virtualization"),
_add("Intel SMM", TRUSTED_EXECUTION, RESTRICTED, manufacturer="Intel",
     aliases=("smm", "system management mode"),
     notes="System Management Mode — legacy, high privilege, ring -2"),

# -- Self-encrypting drives / storage encryption controllers --------------- #
_add("Opal 2.0 SED", SELF_ENCRYPTING_DRIVE, ALLOWED, manufacturer="TCG Storage",
     aliases=("opal", "opal 2", "opal2", "tcg opal", "sed", "self-encrypting drive", "sed opal"),
     notes="TCG Opal 2.0 self-encrypting drive"),
_add("Opalite SED", SELF_ENCRYPTING_DRIVE, RESTRICTED, manufacturer="TCG Storage",
     aliases=("opalite",), notes="Opalite lightweight SED"),
_add("Pyrite SED", SELF_ENCRYPTING_DRIVE, DISALLOWED, manufacturer="TCG Storage",
     aliases=("pyrite",), notes="Pyrite — access control WITHOUT data encryption; not a real SED"),
_add("Enterprise SSC SED", SELF_ENCRYPTING_DRIVE, ALLOWED, manufacturer="TCG Storage",
     aliases=("enterprise ssc", "ssc", "sed enterprise"),
     notes="TCG Storage Security Subsystem Class (enterprise SED)"),
_add("BitLocker (software)", SELF_ENCRYPTING_DRIVE, RESTRICTED, manufacturer="Microsoft",
     aliases=("bitlocker",), notes="software full-disk encryption; hardware offload when SED present"),

# -- Management controllers (BMC) ----------------------------------------- #
_add("IPMI", MANAGEMENT_CONTROLLER, DEPRECATED,
     aliases=("ipmi", "ipmi 1.5", "ipmi 2.0", "bmc ipmi"),
     notes="IPMI BMC protocol; history of vulns; prefer Redfish + strong creds"),
_add("Redfish BMC", MANAGEMENT_CONTROLLER, ALLOWED, manufacturer="DMTF",
     aliases=("redfish", "bmc redfish", "idrac redfish", "ilo redfish"),
     attestation=True, notes="DMTF Redfish secure BMC management"),
_add("iDRAC", MANAGEMENT_CONTROLLER, RESTRICTED, manufacturer="Dell",
     aliases=("idrac", "dell idrac", "idrac9", "idrac8"),
     notes="Dell iDRAC; segment + update firmware"),
_add("iLO", MANAGEMENT_CONTROLLER, RESTRICTED, manufacturer="HPE",
     aliases=("ilo", "hpe ilo", "integrated lights-out", "ilo5", "ilo6"),
     notes="HPE Integrated Lights-Out; segment + update"),
_add("IMM/XCC", MANAGEMENT_CONTROLLER, RESTRICTED, manufacturer="Lenovo",
     aliases=("imm", "xcc", "lenovo xcc", "thinksystem xcc"),
     notes="Lenovo XCC/IMM; segment + update"),

# -- Hardware RNG / entropy sources --------------------------------------- #
_add("RDRAND/RDSEED", HARDWARE_RNG, ALLOWED, manufacturer="Intel/AMD",
     aliases=("rdrand", "rdseed", "rdrand/rdseed"),
     notes="x86 on-chip DRBG/entropy instruction"),
_add("ARM RNDR/RNDRRS", HARDWARE_RNG, ALLOWED, manufacturer="ARM",
     aliases=("rndr", "rndrrs", "arm rng"),
     notes="ARMv8.5 FEAT_RNG true-random register"),
_add("HWRNG (generic)", HARDWARE_RNG, ALLOWED,
     aliases=("hwrng", "hw rng", "hardware rng", "trng"),
     notes="dedicated hardware true-random generator"),

# -- Crypto accelerators / cards ------------------------------------------ #
_add("Intel QAT", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="Intel",
     aliases=("qat", "quickassist", "intel qat", "qat adapter"),
     notes="Intel QuickAssist crypto/compression accelerator"),
_add("NVIDIA GPU Crypto", CRYPTO_ACCELERATOR, RESTRICTED, manufacturer="NVIDIA",
     aliases=("nvidia crypto", "gpu crypto", "cuda crypto"),
     notes="GPU crypto acceleration (also used for crypto-mining/cracking)"),
_add("IBM Crypto Express", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="IBM",
     aliases=("crypto express", "cex", "ibm cex", "4769", "4770", "ep11"),
     quantum_resistant=True, notes="IBM Z Crypto Express coprocessor (EP11, PQC support)"),
_add("Marvell OCTEON", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="Marvell",
     aliases=("octeon", "marvell octeon", "cavium octeon"),
     notes="Marvell/Cavium OCTEON crypto/network accelerator"),
_add("PCAL9xxx / SafeXcel", CRYPTO_ACCELERATOR, RESTRICTED, manufacturer="Marvell",
     aliases=("safexcel", "safeXcel", "inside secure"),
     notes="SafeXcel/Inside Secure crypto engine"),

# -- CPU crypto instruction sets (capabilities, not devices) -------------- #
_add("AES-NI", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="Intel/AMD",
     aliases=("aesni", "aes-ni", "aes"), notes="x86 AES hardware acceleration"),
_add("SHA-NI", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="Intel/AMD",
     aliases=("shani", "sha-ni", "sha_ni", "sha"), notes="x86 SHA-1/256 hardware acceleration"),
_add("VAES", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="Intel/AMD",
     aliases=("vaes", "vector aes"), notes="Vector AES (AVX-512) acceleration"),
_add("PCLMULQDQ", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="Intel/AMD",
     aliases=("pclmulqdq", "pclmul"), notes="carry-less multiplication (GHASH)"),
_add("GFNI", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="Intel/AMD",
     aliases=("gfni",), notes="Galois Field New Instructions"),
_add("ARM Cryptography Extensions", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="ARM",
     aliases=("arm crypto", "crypto extensions", "asimd crypto", "aes arm", "sha arm"),
     notes="ARMv8 AES/SHA/PMULL crypto extensions"),
_add("S390 CCA/CPACF", CRYPTO_ACCELERATOR, ALLOWED, manufacturer="IBM",
     aliases=("cpacf", "cca", "s390 crypto", "msa"), quantum_resistant=True,
     notes="IBM Z CPACF/Message Security Assist crypto instructions"),


@dataclass(frozen=True)
class HardwareInfo:
    """A classified cryptographic hardware device or feature."""

    raw: str
    canonical: str
    category: str
    status: str = UNKNOWN
    manufacturer: str = ""
    recognized: bool = True
    quantum_resistant: bool = False
    attestation: bool = False
    notes: str = ""
    risk_reason: str = ""

    @property
    def is_root_of_trust(self) -> bool:
        return self.category == ROOT_OF_TRUST

    @property
    def weak_or_missing_trust(self) -> bool:
        return self.status in (DEPRECATED, DISALLOWED, UNKNOWN)

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "device": self.canonical,
            "category": self.category,
            "status": self.status,
            "manufacturer": self.manufacturer,
            "recognized": self.recognized,
            "quantum_resistant": self.quantum_resistant,
            "attestation": self.attestation,
            "notes": self.notes,
            "risk_reason": self.risk_reason,
        }


def _unknown(raw: str, reason: str = "") -> HardwareInfo:
    return HardwareInfo(
        raw=raw, canonical=raw or "unknown-device", category="unknown", status=UNKNOWN,
        recognized=False, risk_reason=reason or "unrecognized hardware — human review",
    )


def classify_hardware(name: str, *, kind: str = "", manufacturer: str = "") -> HardwareInfo:
    """Classify a hardware device/feature by model/vendor string.

    ``kind`` may be a device class (tpm/hsm/secure_element/tee/sed/bmc/...) to
    disambiguate; ``manufacturer`` helps pick a vendor record. Tolerates
    version suffixes and marketing names ('YubiKey 5C NFC', 'Luna SA 7',
    'Intel(R) SGX', 'TPM 2.0 (Infineon)').
    """
    raw = str(name or "").strip()
    key = _nk(raw)
    if not key:
        return _unknown(raw)

    kind_l = str(kind or "").lower()

    # TPM version special-case (most common signal): '2.0' / '1.2' / 'tpm2'
    tpm_version = None
    if "tpm" in kind_l or "TPM" in raw:
        if re.search(r"2(\.0)?", raw) and "1.2" not in raw and key not in ("TPM12",):
            tpm_version = "TPM20"
        elif "1.2" in raw or key == "TPM12":
            tpm_version = "TPM12"
    if tpm_version == "TPM20":
        return _info(raw, _DEVICES[_nk("TPM 2.0")])
    if tpm_version == "TPM12":
        return _info(raw, _DEVICES[_nk("TPM 1.2")])

    rec: _Hw | None = None
    if key in _DEVICES:
        rec = _DEVICES[key]
    elif key in _BY_ALIAS:
        rec = _BY_ALIAS[key]
    else:
        # token scan for model/vendor words: 'Thales Luna SA 7', 'Infineon SLB9670'
        tokens = [_nk(t) for t in re.split(r"[^A-Za-z0-9.]+", raw.upper())]
        # prefer the longest alias hit (more specific)
        best: tuple[int, _Hw] | None = None
        for alias, hw in _BY_ALIAS.items():
            if len(alias) < 3:
                continue
            if alias in key or any(alias == t or alias in t for t in tokens if len(t) >= 3):
                if best is None or len(alias) > best[0]:
                    best = (len(alias), hw)
        if best:
            rec = best[1]

    # manufacturer hint can disambiguate (e.g. 'HSM' + 'Thales')
    if rec is None and manufacturer:
        mkey = _nk(manufacturer)
        for hw in _BY_ALIAS.values():
            if hw.manufacturer and _nk(hw.manufacturer) == mkey:
                rec = hw
                break

    if rec is None:
        return _unknown(raw)
    return _info(raw, rec)


def _info(raw: str, rec: _Hw) -> HardwareInfo:
    return HardwareInfo(
        raw=raw, canonical=rec.canonical, category=rec.category, status=rec.status,
        manufacturer=rec.manufacturer, recognized=True,
        quantum_resistant=rec.quantum_resistant, attestation=rec.attestation,
        notes=rec.notes, risk_reason=_risk_reason(rec),
    )


def _risk_reason(rec: _Hw) -> str:
    if rec.status == DISALLOWED:
        return f"{rec.canonical} must not be relied on — {rec.notes}"
    if rec.status == DEPRECATED:
        return f"{rec.canonical} is obsolete/weak — {rec.notes}"
    if rec.status == REQUIRED:
        return f"{rec.canonical} is the expected root of trust baseline"
    if rec.status == RESTRICTED:
        return f"{rec.canonical} acceptable with caveats — {rec.notes}"
    return ""


def tpm_verdict(version: str | None, present: bool = True) -> HardwareInfo:
    """Convenience: verdict for a TPM given just its version string."""
    if not present:
        return HardwareInfo(
            raw="no-tpm", canonical="No TPM", category=ROOT_OF_TRUST, status=DISALLOWED,
            recognized=True, risk_reason="no TPM present — no hardware root of trust for measured/secure boot",
        )
    v = str(version or "").strip()
    if v.startswith("2"):
        return _info(f"TPM {v}", _DEVICES[_nk("TPM 2.0")])
    if v.startswith("1"):
        return _info(f"TPM {v}", _DEVICES[_nk("TPM 1.2")])
    return _info(f"TPM {v}", _DEVICES[_nk("Trusted Platform Module")])


def risk_severity(info: HardwareInfo, *, internet_facing: bool = False) -> str:
    """Deterministic severity for a hardware finding."""
    if not info.recognized:
        return "MEDIUM"
    if info.status == UNKNOWN:
        return "MEDIUM"  # e.g. TPM of undetermined version — needs review
    if info.status == DISALLOWED:
        return "HIGH"  # broken/fake trust control (no-TPM, Pyrite non-SED, …)
    if info.status == DEPRECATED:
        return "MEDIUM" if info.category == ROOT_OF_TRUST else "LOW"
    if info.status == REQUIRED:
        return "INFO"
    if info.status == RESTRICTED:
        return "LOW"
    return "INFO"


def catalog() -> list[dict[str, Any]]:
    """The full hardware catalog (for APIs / dashboards)."""
    out: dict[str, dict[str, Any]] = {}
    for hw in _DEVICES.values():
        if hw.canonical in out:
            continue
        out[hw.canonical] = HardwareInfo(
            raw=hw.canonical, canonical=hw.canonical, category=hw.category, status=hw.status,
            manufacturer=hw.manufacturer, recognized=True, quantum_resistant=hw.quantum_resistant,
            attestation=hw.attestation, notes=hw.notes, risk_reason=_risk_reason(hw),
        ).to_dict()
    return sorted(out.values(), key=lambda e: (e["category"], e["device"]))
