"""Bounded .NET assembly analysis (§17 Phase 4).

A .NET assembly is a PE with a CLR runtime header (data directory 14).
We parse the CLR header and the metadata root (BSJB) — stream headers
and the #Strings heap — within bounded reads. Type names from the
strings heap feed crypto detection (System.Security.Cryptography.*);
anything beyond the bounded scope is named unknown (§14).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_MAX_STRINGS = 4096
_MAX_STRING = 512


@dataclass
class DotNetReport:
    valid: bool
    reason: str = ""
    runtime_version: str = ""
    assembly_name: str = ""
    streams: List[str] = field(default_factory=list)
    type_names: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid, "reason": self.reason,
            "runtime_version": self.runtime_version,
            "assembly_name": self.assembly_name, "streams": self.streams,
            "type_names": self.type_names[:200],
            "limitations": self.limitations,
        }


def parse_dotnet(data: bytes) -> DotNetReport:
    report = DotNetReport(valid=False)
    try:
        return _parse(data, report)
    except (IndexError, ValueError, OverflowError) as exc:
        report.reason = f"malformed CLR metadata — refused safely: {exc}"
        report.limitations.append("structure parsing failed safely (§14)")
        return report


def _parse(data: bytes, report: DotNetReport) -> DotNetReport:
    from binary_intelligence.pe import parse_pe
    pe = parse_pe(data)
    if not pe.valid:
        report.reason = "not a PE — .NET assemblies are PE files with a CLR header"
        return report
    # locate data directory 14 (CLR runtime header) through the PE parse
    if len(data) < 0x40:
        report.reason = "file too short"
        return report
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    opt = e_lfanew + 24
    magic = int.from_bytes(data[opt:opt + 2], "little")
    pe32_plus = magic == 0x20B
    dd_off = opt + (112 if pe32_plus else 96)
    num_dirs = int.from_bytes(data[opt + (108 if pe32_plus else 96):
                                   opt + (112 if pe32_plus else 96)], "little")
    if num_dirs <= 14:
        report.reason = "no CLR runtime header directory — not a .NET assembly"
        return report
    clr_rva = int.from_bytes(data[dd_off + 14 * 8:dd_off + 14 * 8 + 4], "little")
    if not clr_rva:
        report.reason = "CLR runtime header directory is empty — not a .NET assembly"
        return report

    # resolve RVA through PE sections
    sections = pe.sections
    def rva_to_off(rva: int) -> Optional[int]:
        for section in sections:
            va, vsz = section["virtual_address"], section["virtual_size"]
            raw, rsz = section["raw_offset"], section["raw_size"]
            if va <= rva < va + max(vsz, rsz):
                off = raw + (rva - va)
                return off if off < len(data) else None
        return None

    clr_off = rva_to_off(clr_rva)
    if clr_off is None or clr_off + 72 > len(data):
        report.reason = "CLR header outside the file — refused safely"
        return report
    # CLR header: cb(4) major(2) minor(2) metadata RVA(4) metadata size(4) ...
    metadata_rva = int.from_bytes(data[clr_off + 8:clr_off + 12], "little")
    meta_off = rva_to_off(metadata_rva)
    if meta_off is None or meta_off + 20 > len(data):
        report.reason = "metadata root outside the file — refused safely"
        return report
    if data[meta_off:meta_off + 4] != b"BSJB":
        report.reason = "metadata root lacks the BSJB signature"
        return report
    version_len = int.from_bytes(data[meta_off + 12:meta_off + 16], "little")
    if version_len > 256:
        report.reason = "runtime version string exceeds the bounded limit"
        return report
    report.runtime_version = data[meta_off + 16:
                                  meta_off + 16 + version_len].split(
        b"\x00")[0].decode("utf-8", errors="replace")
    stream_headers = meta_off + 16 + ((version_len + 3) & ~3) + 2
    stream_count = int.from_bytes(data[stream_headers - 2:stream_headers],
                                 "little") if stream_headers >= 2 else 0
    if stream_count > 32:
        report.reason = (f"stream count {stream_count} exceeds the bounded "
                         "limit 32 — refused, not truncated")
        return report
    cursor = stream_headers
    strings_heap = b""
    for _ in range(stream_count):
        if cursor + 8 > len(data):
            report.limitations.append("stream headers truncated — unknown, "
                                      "never guessed")
            break
        offset = int.from_bytes(data[cursor:cursor + 4], "little")
        size = int.from_bytes(data[cursor + 4:cursor + 8], "little")
        name_start = cursor + 8
        name_end = data.find(b"\x00", name_start, name_start + 32)
        if name_end == -1:
            break
        name = data[name_start:name_end].decode("ascii", "replace")
        report.streams.append(name)
        cursor = name_end + 1
        cursor += (4 - (cursor - (name_end + 1)) % 4) % 4
        cursor = name_end + 1 + ((4 - (name_end + 1 - name_end) % 4) % 4)
        # re-align to 4-byte boundary from stream header start
        cursor = name_end + 1
        while (cursor - (cursor - (name_end + 1))) and (cursor % 4):
            cursor += 1
        heap_off = meta_off + offset
        if name == "#Strings" and size and heap_off + size <= len(data):
            strings_heap = data[heap_off:heap_off + size]
        if name in ("#~", "#-"):
            report.limitations.append(
                "metadata tables stream present — row-level parsing is "
                "outside this version's bounded scope; names come from "
                "the strings heap")

    if strings_heap:
        parts = strings_heap.split(b"\x00")
        for part in parts[:_MAX_STRINGS]:
            text = part.decode("utf-8", errors="replace")[:_MAX_STRING]
            if text and ("." in text or "/" in text):
                report.type_names.append(text.replace("/", "."))
        # the assembly name is conventionally the first non-empty string
        for part in parts:
            text = part.decode("utf-8", errors="replace")
            if text and all(c.isalnum() or c in "._-" for c in text):
                report.assembly_name = text
                break
    report.valid = True
    report.reason = ".NET metadata parsed within bounded reads"
    return report
