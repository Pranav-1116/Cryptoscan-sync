"""Bounded PE structural parser (§4 Stage 2, §14).

Parses DOS/COFF/optional headers, the section table, import and export
tables and signature presence with bounded reads; every RVA is resolved
through the section table and validated against the file length before
access. A malformed field fails safe with its reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_MACHINES = {
    0x014C: "x86", 0x01C0: "arm", 0x01C4: "armv7",
    0x8664: "x86-64", 0xAA64: "arm64",
}

_MAX_SECTIONS = 96
_MAX_IMPORTS = 2048
_MAX_NAME = 512


@dataclass
class PEReport:
    valid: bool
    reason: str = ""
    pe32_plus: bool = False
    architecture: str = ""
    sections: List[Dict[str, Any]] = field(default_factory=list)
    imported_dlls: List[str] = field(default_factory=list)
    imported_functions: List[str] = field(default_factory=list)
    exported_functions: List[str] = field(default_factory=list)
    has_debug: bool = False
    has_authenticode: bool = False
    has_resources: bool = False
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid, "reason": self.reason,
            "pe32_plus": self.pe32_plus, "architecture": self.architecture,
            "sections": self.sections, "imported_dlls": self.imported_dlls,
            "imported_functions": self.imported_functions,
            "exported_functions": self.exported_functions,
            "has_debug": self.has_debug,
            "has_authenticode": self.has_authenticode,
            "has_resources": self.has_resources,
            "limitations": self.limitations,
        }


def parse_pe(data: bytes) -> PEReport:
    report = PEReport(valid=False)
    try:
        return _parse(data, report)
    except (IndexError, ValueError, OverflowError) as exc:
        report.valid = False
        report.reason = f"malformed PE — bounded parser refused: {exc}"
        report.limitations.append("structure parsing failed safely (§14)")
        return report


def _parse(data: bytes, report: PEReport) -> PEReport:
    if len(data) < 0x40 or data[:2] != b"MZ":
        report.reason = "not a PE file (no MZ stub)"
        return report
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        report.reason = "e_lfanew points outside the file — malformed"
        return report
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        report.reason = "MZ stub without a PE signature"
        return report

    coff = e_lfanew + 4
    machine = int.from_bytes(data[coff:coff + 2], "little")
    n_sections = int.from_bytes(data[coff + 2:coff + 4], "little")
    opt_size = int.from_bytes(data[coff + 16:coff + 18], "little")
    report.architecture = _MACHINES.get(machine, f"unrecognized(machine=0x{machine:04x})")

    opt = coff + 20
    if opt + opt_size > len(data) or opt_size < 2:
        report.reason = "optional header exceeds the file — malformed"
        return report
    magic = int.from_bytes(data[opt:opt + 2], "little")
    if magic == 0x20B:
        report.pe32_plus = True
    elif magic == 0x10B:
        report.pe32_plus = False
    else:
        report.reason = f"unknown optional-header magic 0x{magic:04x}"
        return report

    # data directories: PE32+ starts at opt+112, PE32 at opt+96
    dd_off = opt + (112 if report.pe32_plus else 96)
    num_dirs = int.from_bytes(data[opt + (108 if report.pe32_plus else 92):
                                   opt + (112 if report.pe32_plus else 96)],
                             "little") if opt_size > (108 if report.pe32_plus else 96) else 0

    def directory(index: int) -> Tuple[int, int]:
        if index >= num_dirs:
            return 0, 0
        base = dd_off + index * 8
        if base + 8 > len(data):
            return 0, 0
        return (int.from_bytes(data[base:base + 4], "little"),
                int.from_bytes(data[base + 4:base + 8], "little"))

    export_rva, export_size = directory(0)
    import_rva, import_size = directory(1)
    resource_rva, _ = directory(2)
    debug_rva, _ = directory(6)
    cert_off, cert_size = directory(4)   # security directory holds a FILE offset

    if n_sections > _MAX_SECTIONS:
        report.reason = (f"section count {n_sections} exceeds the bounded "
                         f"limit {_MAX_SECTIONS} — refused, not truncated")
        return report

    sections: List[Tuple[str, int, int, int, int]] = []
    sec_base = opt + opt_size
    for i in range(n_sections):
        base = sec_base + i * 40
        if base + 40 > len(data):
            report.limitations.append("section table truncated at file end")
            break
        name = data[base:base + 8].split(b"\x00")[0].decode("ascii", "replace")
        virt_size = int.from_bytes(data[base + 8:base + 12], "little")
        virt_addr = int.from_bytes(data[base + 12:base + 16], "little")
        raw_size = int.from_bytes(data[base + 16:base + 20], "little")
        raw_off = int.from_bytes(data[base + 20:base + 24], "little")
        chars = int.from_bytes(data[base + 36:base + 40], "little")
        sections.append((name, virt_addr, virt_size, raw_off, raw_size))
        report.sections.append({
            "name": name, "virtual_address": virt_addr,
            "virtual_size": virt_size, "raw_offset": raw_off,
            "raw_size": raw_size, "executable": bool(chars & 0x20000000),
        })

    def rva_to_off(rva: int) -> Optional[int]:
        for _n, va, vsz, raw, rsz in sections:
            span = max(vsz, rsz)
            if va <= rva < va + span:
                off = raw + (rva - va)
                return off if off < len(data) else None
        return None

    def cstr_off(off: int) -> str:
        if off is None or off < 0 or off >= len(data):
            return ""
        end = data.find(b"\x00", off, min(off + _MAX_NAME, len(data)))
        if end == -1:
            end = min(off + _MAX_NAME, len(data))
        return data[off:end].decode("utf-8", errors="replace")

    # imports: descriptor array (20 bytes each) terminated by a zero entry
    if import_rva:
        desc_off = rva_to_off(import_rva)
        for i in range(_MAX_IMPORTS):
            base = (desc_off or 0) + i * 20
            if desc_off is None or base + 20 > len(data):
                break
            oft = int.from_bytes(data[base:base + 4], "little")
            name_rva = int.from_bytes(data[base + 12:base + 16], "little")
            ft = int.from_bytes(data[base + 16:base + 20], "little")
            if not (oft or name_rva or ft):
                break
            dll = cstr_off(rva_to_off(name_rva))
            if dll:
                report.imported_dlls.append(dll)
            thunk_rva = oft or ft
            thunk_off = rva_to_off(thunk_rva)
            if thunk_off is None:
                report.limitations.append(
                    f"import thunk table for {dll or '?'} is outside the "
                    "file — unresolved, never invented")
                continue
            step = 8 if report.pe32_plus else 4
            for j in range(_MAX_IMPORTS):
                tb = thunk_off + j * step
                if tb + step > len(data):
                    break
                entry = int.from_bytes(data[tb:tb + step], "little")
                if entry == 0:
                    break
                ordinal_flag = 1 << (63 if report.pe32_plus else 31)
                if entry & ordinal_flag:
                    report.imported_functions.append(f"ordinal#{entry & 0xFFFF}")
                    continue
                fn = cstr_off(rva_to_off(entry + 2) if entry else None)
                if fn:
                    report.imported_functions.append(fn)

    # exports: export directory (40 bytes)
    if export_rva:
        exp_off = rva_to_off(export_rva)
        if exp_off is not None and exp_off + 40 <= len(data):
            num_names = int.from_bytes(data[exp_off + 24:exp_off + 28], "little")
            names_rva = int.from_bytes(data[exp_off + 32:exp_off + 36], "little")
            names_off = rva_to_off(names_rva)
            for i in range(min(num_names, _MAX_IMPORTS)):
                nb = (names_off or 0) + i * 4
                if names_off is None or nb + 4 > len(data):
                    break
                fn = cstr_off(rva_to_off(
                    int.from_bytes(data[nb:nb + 4], "little")))
                if fn:
                    report.exported_functions.append(fn)

    report.has_resources = bool(resource_rva)
    report.has_debug = bool(debug_rva)
    report.has_authenticode = bool(cert_off and cert_size)
    if report.has_authenticode:
        report.limitations.append(
            "an Authenticode signature is present — signature validity is "
            "verified separately, presence is not trust")

    report.valid = True
    report.reason = "PE structure parsed within bounded reads"
    return report
