#!/usr/bin/env python3
"""CryptoScan hardware scanner — local host, stdlib only.

Detects the host's cryptographic hardware and CPU crypto capabilities, reading
PUBLIC METADATA ONLY. It never touches secret material (no TPM keys/endorsement
data, no HSM partitions/PINs, no smart-card PINs).

Collected:
  • CPU     — vendor/model/arch, cores/threads, microcode, and the crypto
              instruction extensions (AES-NI, SHA-NI, RDRAND/RDSEED, GFNI,
              VAES/VPCLMULQDQ, PCLMULQDQ, SGX/TDX/SEV/SME trusted execution).
              Presence is recorded as a hardware CAPABILITY, never proof of use.
  • TPM     — presence + version (1.2/2.0) via /sys/class/tpm and /dev/tpm*.
  • HSM     — presence hints (PKCS#11 modules, vendor libs/tools) — metadata only.
  • Smart card / secure element — PC/SC readers (pcscd, /dev/pcsc, CCID).

Usage:
  python3 hw_scan.py                 # one-screen verdict
  python3 hw_scan.py --json          # full JSON
  python3 hw_scan.py -o hw.json      # write JSON to file (verdict still printed)
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import sys
from pathlib import Path

# --- CPU ---------------------------------------------------------------

_CRYPTO_EXT_ALIASES = {
    "aes": "AES", "aesni": "AES",
    "sha": "SHA", "sha_ni": "SHA-NI", "shani": "SHA-NI",
    "rdrand": "RDRAND", "rdseed": "RDSEED",
    "pclmulqdq": "PCLMULQDQ", "gfni": "GFNI",
    "vaes": "VAES", "vpclmulqdq": "VPCLMULQDQ",
    "sgx": "SGX", "tdx": "TDX", "sev": "SEV", "sme": "SME", "amx": "AMX",
}
_TRUSTED_EXEC = ("SGX", "TDX", "SEV", "SME", "AMX")


def scan_cpu() -> dict:
    info = {
        "vendor": None, "model": None, "architecture": platform.machine() or None,
        "core_count": None, "thread_count": os.cpu_count(),
        "microcode_version": None, "instruction_extensions": [],
        "aes_acceleration": False, "sha_acceleration": False,
        "hardware_rng": False, "trusted_execution": False,
    }
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        text = cpuinfo.read_text(errors="replace")
        m = re.search(r"vendor_id\s*:\s*(\S+)", text)
        if m:
            info["vendor"] = m.group(1)
        m = re.search(r"model name\s*:\s*(.+)", text)
        if m:
            info["model"] = m.group(1).strip()
        m = re.search(r"cpu cores\s*:\s*(\d+)", text)
        if m:
            info["core_count"] = int(m.group(1))
        m = re.search(r"microcode\s*:\s*(\S+)", text)
        if m:
            info["microcode_version"] = m.group(1)
        ext: list[str] = []
        for flags in re.findall(r"flags\s*:\s*([^\n]+)", text):
            for tok in flags.split():
                name = _CRYPTO_EXT_ALIASES.get(tok.lower(), tok.upper())
                if name not in ext:
                    ext.append(name)
        crypto_ext = [e for e in ext if e in {
            "AES", "SHA", "SHA-NI", "RDRAND", "RDSEED", "PCLMULQDQ", "GFNI",
            "VAES", "VPCLMULQDQ", *_TRUSTED_EXEC}]
        info["instruction_extensions"] = crypto_ext
        info["aes_acceleration"] = bool({"AES", "VAES"} & set(crypto_ext))
        info["sha_acceleration"] = bool({"SHA", "SHA-NI"} & set(crypto_ext))
        info["hardware_rng"] = bool({"RDRAND", "RDSEED"} & set(crypto_ext))
        info["trusted_execution"] = bool(set(_TRUSTED_EXEC) & set(crypto_ext))
    else:
        # macOS / non-/proc fallback: minimal, honest
        info["vendor"] = platform.processor() or None
        info["note"] = "no /proc/cpuinfo; crypto extensions not enumerated on this OS"
    return info


# --- TPM ---------------------------------------------------------------

def scan_tpm() -> dict:
    tpm = {"present": False, "version": None, "interface": None,
           "device": None, "manufacturer": None, "evidence": []}
    # sysfs (Linux)
    sys_tpm = Path("/sys/class/tpm")
    if sys_tpm.is_dir():
        for dev in sorted(sys_tpm.glob("tpm*")):
            tpm["present"] = True
            tpm["evidence"].append(f"sysfs:{dev}")
            vmaj = (dev / "tpm_version_major")
            if vmaj.exists():
                tpm["version"] = vmaj.read_text().strip()
                tpm["interface"] = "TPM 2.0" if tpm["version"] == "2" else f"TPM {tpm['version']}"
            desc = (dev / "device" / "description")
            if desc.exists():
                tpm["manufacturer"] = desc.read_text().strip()
            break
    # device nodes
    for node in ("/dev/tpmrm0", "/dev/tpm0", "/dev/tpm"):
        if Path(node).exists():
            tpm["present"] = True
            tpm["device"] = node
            tpm["evidence"].append(f"devnode:{node}")
            if not tpm["interface"]:
                tpm["interface"] = "TPM device node"
    # optional tooling (public metadata only; not required)
    for tool in ("tpm2_getrandom", "tpm2_pcrread", "tpmtool"):
        if shutil.which(tool):
            tpm["evidence"].append(f"tool:{tool}")
    return tpm


# --- HSM / PKCS#11 -----------------------------------------------------
# A PKCS#11 *interface* is not an HSM: OpenSC provides a PKCS#11 module for
# smart cards / secure elements, while SoftHSM is a software HSM and the
# vendor paths below are real HSM appliances. Classify them separately so an
# OpenSC install is never (mis)reported as an HSM.

_HSM_VENDOR_LIBS = (
    "/opt/nfast/tool/hardserver",          # Entrust nShield
    "/usr/safenet/lunaclient/bin/vtl",     # Thales Luna / SafeNet
    "/usr/local/bin/vtl",
    "/usr/lib/libCryptoki2.so",            # SafeNet Luna
    "/usr/local/utimaco/bin/csadm",        # Utimaco SecurityServer
)
_HSM_SOFTWARE_LIBS = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm.so",
)
_HSM_VENDOR_TOOLS = ("vtl", "ctconf", "hsmstate", "csadm", "nfast")
_HSM_SOFTWARE_TOOLS = ("softhsm2-util", "softhsm-util")
# Smart-card / generic PKCS#11 middleware (NOT an HSM):
_PKCS11_SMARTCARD_LIBS = (
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
)
_PKCS11_SMARTCARD_TOOLS = ("pkcs11-tool", "opensc-tool", "p11tool", "pkcs15-tool")


def scan_hsm() -> dict:
    hsm = {"present": False, "kind": None, "interfaces": [], "evidence": []}
    for path in _HSM_VENDOR_LIBS:
        if Path(path).exists():
            hsm["present"] = True
            hsm["kind"] = "vendor-appliance"
            hsm["evidence"].append(f"vendor:{path}")
    for path in _HSM_SOFTWARE_LIBS:
        if Path(path).exists():
            hsm["present"] = True
            hsm["kind"] = hsm["kind"] or "software (SoftHSM)"
            hsm["evidence"].append(f"softhsm:{path}")
    for tool in _HSM_VENDOR_TOOLS:
        if shutil.which(tool):
            hsm["present"] = True
            hsm["kind"] = hsm["kind"] or "vendor-appliance"
            hsm["evidence"].append(f"tool:{tool}")
    for tool in _HSM_SOFTWARE_TOOLS:
        if shutil.which(tool):
            hsm["present"] = True
            hsm["kind"] = hsm["kind"] or "software (SoftHSM)"
            hsm["evidence"].append(f"tool:{tool}")
    if hsm["present"]:
        hsm["interfaces"] = ["PKCS#11"]
    return hsm


# --- Smart card / secure element --------------------------------------

def scan_smartcard() -> dict:
    sc = {"present": False, "interface": None, "pkcs11_middleware": [], "evidence": []}
    if shutil.which("pcscd") or Path("/usr/sbin/pcscd").exists():
        sc["evidence"].append("pcscd daemon present (PC/SC resource manager)")
    for path in _PKCS11_SMARTCARD_LIBS:
        if Path(path).exists():
            sc["present"] = True
            sc["pkcs11_middleware"].append("OpenSC PKCS#11")
            sc["evidence"].append(f"pkcs11-module:{path}")
    for tool in _PKCS11_SMARTCARD_TOOLS:
        if shutil.which(tool):
            sc["present"] = True
            sc["evidence"].append(f"tool:{tool}")
    for dev in Path("/dev").glob("pcsc*"):
        sc["present"] = True
        sc["evidence"].append(f"devnode:{dev}")
    if sc["present"] or shutil.which("pcsc_scan"):
        sc["interface"] = "PC/SC"
    sc["pkcs11_middleware"] = sorted(set(sc["pkcs11_middleware"]))
    return sc



# --- canonical hardware classification --------------------------------- #

_HSM_VENDOR_BY_PATH = (
    ("nfast", "nShield Connect"),
    ("lunaclient", "Luna SA 7"),
    ("libcryptoki2", "Luna SA 7"),
    ("/vtl", "Luna SA 7"),
    ("utimaco", "Utimaco SecurityServer"),
    ("/csadm", "Utimaco SecurityServer"),
    ("cloudhsm", "CloudHSM"),
)


def _hsm_vendor_label(hsm: dict) -> str | None:
    low = " ".join(hsm.get("evidence") or []).lower()
    for needle, label in _HSM_VENDOR_BY_PATH:
        if needle in low:
            return label
    return None


def classify_hardware_scan(d: dict) -> dict:
    """Canonical naming + verdict for crypto-hardware signals (metadata only)."""
    try:
        from shared_models.hardware_registry import (
            classify_hardware, risk_severity, tpm_verdict,
        )
    except Exception:
        return {"available": False, "devices": [], "counts": {}}

    devices: list[dict] = []

    def add(info) -> None:
        doc = info.to_dict()
        doc["severity"] = risk_severity(info)
        devices.append(doc)

    tpm = d.get("tpm") or {}
    add(tpm_verdict(tpm.get("version") if tpm.get("present") else None,
                    present=bool(tpm.get("present"))))

    hsm = d.get("hsm") or {}
    if hsm.get("present"):
        if str(hsm.get("kind") or "").startswith("software"):
            add(classify_hardware("SoftHSM2", kind="hsm"))
        else:
            add(classify_hardware(_hsm_vendor_label(hsm) or "HSM appliance", kind="hsm"))

    ext_to_kind = {
        "AES": ("AES-NI", "cpu_feature"), "VAES": ("VAES", "cpu_feature"),
        "SHA": ("SHA-NI", "cpu_feature"), "SHA-NI": ("SHA-NI", "cpu_feature"),
        "RDRAND": ("RDRAND", "rng"), "RDSEED": ("RDSEED", "rng"),
        "SGX": ("Intel SGX", "tee"), "TDX": ("TDX", "tee"),
        "SEV": ("SEV-SNP", "tee"), "SME": ("SEV-SNP", "tee"),
        "PCLMULQDQ": ("PCLMULQDQ", "cpu_feature"), "GFNI": ("GFNI", "cpu_feature"),
    }
    for ext in (d.get("cpu") or {}).get("instruction_extensions") or []:
        if ext in ext_to_kind:
            name, kind = ext_to_kind[ext]
            ci = classify_hardware(name, kind=kind)
            if ci.recognized:
                add(ci)

    if (d.get("smartcard") or {}).get("present"):
        add(classify_hardware("Smart Card", kind="smart_card"))

    counts: dict[str, int] = {}
    for dev in devices:
        counts[dev["status"]] = counts.get(dev["status"], 0) + 1
    return {
        "available": True,
        "devices": devices,
        "counts": counts,
        "root_of_trust_present": any(
            dev["category"] == "root-of-trust" and dev["status"] in ("REQUIRED", "ALLOWED")
            for dev in devices
        ),
        "hardware_keystore_present": any(
            dev["category"] == "hardware-keystore" for dev in devices
        ),
    }



# --- orchestration + report -------------------------------------------

def collect() -> dict:
    d = {
        "scanner": "cryptoscan-hardware",
        "host": {"hostname": platform.node(), "os": platform.platform(),
                 "architecture": platform.machine()},
        "cpu": scan_cpu(),
        "tpm": scan_tpm(),
        "hsm": scan_hsm(),
        "smartcard": scan_smartcard(),
    }
    d["classified"] = classify_hardware_scan(d)
    return d


def _yesno(flag: bool) -> str:
    return "yes" if flag else "no"


def report(d: dict) -> None:
    h = d["host"]
    print(f"● hardware scan — {h['hostname']}  ({h['os']})")
    cpu = d["cpu"]
    print(f"    CPU        : {cpu.get('model') or cpu.get('vendor') or '?'}")
    print(f"                 cores={cpu.get('core_count') or '?'} "
          f"threads={cpu.get('thread_count') or '?'} "
          f"microcode={cpu.get('microcode_version') or '?'}")
    exts = cpu.get("instruction_extensions") or []
    print(f"    crypto CPU : AES-NI={_yesno(cpu['aes_acceleration'])} "
          f"SHA-NI={_yesno(cpu['sha_acceleration'])} "
          f"HW-RNG(RDRAND/RDSEED)={_yesno(cpu['hardware_rng'])} "
          f"trusted-exec(SGX/TDX/SEV)={_yesno(cpu['trusted_execution'])}")
    if exts:
        print(f"                 extensions: {', '.join(exts)}")
    if cpu.get("note"):
        print(f"                 note: {cpu['note']}")

    tpm = d["tpm"]
    if tpm["present"]:
        print(f"    TPM        : PRESENT {tpm.get('interface') or ''} "
              f"device={tpm.get('device') or '-'} "
              f"mfr={tpm.get('manufacturer') or 'unknown'}")
    else:
        print("    TPM        : not detected (no /sys/class/tpm or /dev/tpm*; "
              "VM/container or TPM disabled in BIOS)")

    hsm = d["hsm"]
    if hsm["present"]:
        print(f"    HSM        : PRESENT ({hsm.get('kind')}) via {', '.join(hsm['interfaces'])}")
        for e in hsm["evidence"]:
            print(f"                 - {e}")
    else:
        print("    HSM        : none detected (no SoftHSM or vendor HSM appliance)")

    sc = d["smartcard"]
    if sc["present"]:
        mw = f"middleware={', '.join(sc['pkcs11_middleware'])}" if sc["pkcs11_middleware"] else "reader present"
        print(f"    smart card : {sc['interface'] or 'PC/SC'} stack present ({mw})")
        for e in sc["evidence"]:
            print(f"                 - {e}")
        print("                 (a card/reader is detected only when plugged in + pcscd running)")
    else:
        print("    smart card : no PKCS#11/PC/SC middleware detected")

    # one-line verdict — TPM/HSM are dedicated crypto hardware; a PC/SC stack
    # alone is middleware, not an HSM.
    if hsm["present"]:
        verdict = "HSM present (metadata only — no secrets accessed)"
    elif tpm["present"]:
        verdict = "TPM 2.0 present — hardware root of trust for keys/attestation (metadata only)"
    elif cpu["aes_acceleration"] and cpu["hardware_rng"]:
        verdict = "no dedicated TPM/HSM, but CPU has AES-NI + hardware RNG (software crypto accelerated)"
    else:
        verdict = "limited hardware crypto support"
    print(f"    VERDICT    : {verdict}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CryptoScan local hardware scanner")
    parser.add_argument("--json", action="store_true", help="emit full JSON instead of the verdict")
    parser.add_argument("-o", "--output", help="write full JSON to this path")
    args = parser.parse_args(argv)

    d = collect()
    if args.output:
        Path(args.output).write_text(json.dumps(d, indent=2))
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        report(d)
        if args.output:
            print(f"\n(full JSON written to {args.output})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
