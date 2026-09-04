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

_HSM_LIB_HINTS = (
    "/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/opensc-pkcs11.so", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/libCryptoki2.so", "/opt/nfast/tool/hardserver",
    "/usr/safenet/lunaclient/bin/vtl", "/usr/local/bin/vtl",
)
_HSM_TOOLS = ("softhsm2-util", "pkcs11-tool", "p11tool", "vtl", "ctconf", "hsmstate")


def scan_hsm() -> dict:
    hsm = {"present": False, "interfaces": [], "evidence": []}
    for path in _HSM_LIB_HINTS:
        if Path(path).exists():
            hsm["present"] = True
            hsm["evidence"].append(f"library:{path}")
            hsm["interfaces"].append("PKCS#11" if "pkcs11" in path.lower() else "HSM")
    for tool in _HSM_TOOLS:
        if shutil.which(tool):
            hsm["present"] = True
            hsm["evidence"].append(f"tool:{tool}")
    hsm["interfaces"] = sorted(set(hsm["interfaces"]))
    return hsm


# --- Smart card / secure element --------------------------------------

def scan_smartcard() -> dict:
    sc = {"present": False, "interface": None, "evidence": []}
    if shutil.which("pcscd") or Path("/usr/sbin/pcscd").exists():
        sc["evidence"].append("pcscd daemon present")
    if shutil.which("opensc-tool") or shutil.which("pcsc_scan"):
        sc["present"] = True
        sc["interface"] = "PC/SC"
        sc["evidence"].append("PC/SC tooling present (reader presence requires pcscd + a card)")
    for dev in Path("/dev").glob("pcsc*"):
        sc["present"] = True
        sc["evidence"].append(f"devnode:{dev}")
    return sc


# --- orchestration + report -------------------------------------------

def collect() -> dict:
    return {
        "scanner": "cryptoscan-hardware",
        "host": {"hostname": platform.node(), "os": platform.platform(),
                 "architecture": platform.machine()},
        "cpu": scan_cpu(),
        "tpm": scan_tpm(),
        "hsm": scan_hsm(),
        "smartcard": scan_smartcard(),
    }


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
        print(f"    HSM        : present hints: {', '.join(hsm['interfaces']) or 'see evidence'}")
        for e in hsm["evidence"]:
            print(f"                 - {e}")
    else:
        print("    HSM        : none detected (no PKCS#11 modules or vendor HSM tools)")

    sc = d["smartcard"]
    if sc["present"]:
        print(f"    smart card : reader tooling present ({sc['interface'] or 'PC/SC'})")
        for e in sc["evidence"]:
            print(f"                 - {e}")
    else:
        print("    smart card : no reader/tooling detected")

    # one-line verdict
    flags = [tpm["present"], hsm["present"], sc["present"]]
    if tpm["present"] or hsm["present"]:
        verdict = "dedicated crypto hardware present (metadata only — no secrets accessed)"
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
