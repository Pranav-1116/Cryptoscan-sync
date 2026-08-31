"""CPU discovery (§5).

Discover CPU vendor/family/model/architecture, instruction extensions,
core/thread count and microcode version. Cryptographic relevance: AES
acceleration, SHA acceleration, hardware RNG, trusted execution,
instruction-set crypto capabilities.

Invariant: presence of an instruction extension is a HARDWARE CAPABILITY,
never proof an application uses it — that requires software evidence
correlation (see hardware/correlation.py).
"""

from __future__ import annotations

import re
from typing import Any

from universal_vendor.hardware.models import CpuInfo

# instruction extensions with crypto relevance
_CRYPTO_EXTENSIONS = ("AES", "SHA", "SHA-NI", "SHA-NI", "RDRAND", "RDSEED",
                      "PCLMULQDQ", "GFNI", "VAES", "VPCLMULQDQ", "SGX", "TDX",
                      "SEV", "SME", "AMX")

_EXTENSION_ALIASES = {
    "aes": "AES", "aesni": "AES", "aes-ni": "AES",
    "sha": "SHA", "sha-ni": "SHA-NI", "sha_ni": "SHA-NI",
    "rdrand": "RDRAND", "rdseed": "RDSEED",
    "pclmulqdq": "PCLMULQDQ", "gfni": "GFNI",
    "vaes": "VAES", "vpclmulqdq": "VPCLMULQDQ",
    "sgx": "SGX", "tdx": "TDX", "sev": "SEV", "sme": "SME",
}


class CpuDiscovery:
    def parse(self, raw: dict[str, Any]) -> CpuInfo:
        """Parse CPU evidence from agent/API metadata."""
        extensions = [str(ext) for ext in raw.get("instruction_extensions") or []]
        # normalize aliases and dedupe
        normalized: list[str] = []
        for ext in extensions:
            name = _EXTENSION_ALIASES.get(ext.lower(), ext)
            if name not in normalized:
                normalized.append(name)
        cpu = CpuInfo(
            vendor=raw.get("vendor"),
            family=str(raw.get("family") or ""),
            model=str(raw.get("model") or ""),
            architecture=raw.get("architecture"),
            instruction_extensions=normalized,
            core_count=_int(raw.get("core_count") or raw.get("cores")),
            thread_count=_int(raw.get("thread_count") or raw.get("threads")),
            microcode_version=raw.get("microcode_version"),
            aes_acceleration=_has(normalized, "AES", "VAES"),
            sha_acceleration=_has(normalized, "SHA", "SHA-NI"),
            hardware_rng=_has(normalized, "RDRAND", "RDSEED"),
            trusted_execution=_has(normalized, "SGX", "TDX", "SEV", "SME", "AMX"),
        )
        return cpu

    def parse_text(self, text: str) -> CpuInfo:
        """Parse /proc/cpuinfo-style flags."""
        flags = re.findall(r"\bflags\s*:\s*([^\n]+)", text)
        extensions: list[str] = []
        for line in flags:
            for token in line.split():
                name = _EXTENSION_ALIASES.get(token.lower(), token)
                if name not in extensions:
                    extensions.append(name)
        vendor = None
        match = re.search(r"vendor_id\s*:\s*(\S+)", text)
        if match:
            vendor = match.group(1)
        model_name = None
        match = re.search(r"model name\s*:\s*(.+)", text)
        if match:
            model_name = match.group(1).strip()
        cores = None
        match = re.search(r"cpu cores\s*:\s*(\d+)", text)
        if match:
            cores = int(match.group(1))
        return CpuInfo(
            vendor=vendor, model=model_name, architecture="x86_64",
            instruction_extensions=extensions, core_count=cores,
            aes_acceleration=_has(extensions, "AES", "VAES"),
            sha_acceleration=_has(extensions, "SHA", "SHA-NI"),
            hardware_rng=_has(extensions, "RDRAND", "RDSEED"),
            trusted_execution=_has(extensions, "SGX", "TDX", "SEV", "SME", "AMX"),
        )

    def to_observation(self, cpu: CpuInfo) -> dict[str, Any]:
        return {"crypto_type": "hardware-capability", "algorithm": "CPU",
                "cpu": cpu.to_dict(),
                "capability_only": True,  # presence ≠ usage (§5)
                "note": "instruction-set presence recorded as hardware "
                        "capability; usage requires software evidence"}


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _has(extensions: list[str], *names: str) -> bool:
    return any(name in extensions for name in names)
