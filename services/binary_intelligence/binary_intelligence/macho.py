"""Bounded Mach-O and universal-binary parser (§1 Stage 1, §4 Stage 2,
§17 Phase 4). 32/64-bit, both endiannesses, fat binaries; load
commands give CPU type, file type, dynamic libraries, symbol table and
UUID. Every read is bounded; a malformed field fails safe (§14).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_MACHO_MAGICS = {
    0xFEEDFACE: ("macho32", "big"),
    0xCEFAEDFE: ("macho32", "little"),
    0xFEEDFACF: ("macho64", "big"),
    0xCFFAEDFE: ("macho64", "little"),
}
_FAT_MAGICS = {0xCAFEBABE: "big", 0xBEBAFECA: "little"}

_CPUTYPES = {
    7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "arm64",
    18: "powerpc", 0x01000012: "powerpc64",
}
_FILETYPES = {1: "object", 2: "execute", 6: "dylib", 8: "bundle", 9: "dylinker", 10: "kext"}

_LC_LOAD_DYLIB = 0xC
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_ID_DYLIB = 0xD
_LC_SYMTAB = 0x2
_LC_UUID = 0x1B
_LC_SEGMENT = 0x1
_LC_SEGMENT_64 = 0x19
_MAX_COMMANDS = 256
_MAX_LIBS = 512
_MAX_SYMBOLS = 4096
_MAX_SLICES = 16


@dataclass
class MachOReport:
    valid: bool
    reason: str = ""
    bitness: int = 0
    endianness: str = ""
    architecture: str = ""
    filetype: str = ""
    uuid: Optional[str] = None
    libraries: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    segments: List[Dict[str, Any]] = field(default_factory=list)
    slices: List[Dict[str, Any]] = field(default_factory=list)   # fat only
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid, "reason": self.reason,
            "bitness": self.bitness, "endianness": self.endianness,
            "architecture": self.architecture, "filetype": self.filetype,
            "uuid": self.uuid, "libraries": self.libraries,
            "symbols": self.symbols[:200], "segments": self.segments,
            "slices": self.slices, "limitations": self.limitations,
        }


def parse_macho(data: bytes) -> MachOReport:
    report = MachOReport(valid=False)
    try:
        return _parse(data, report)
    except (IndexError, ValueError, OverflowError) as exc:
        report.valid = False
        report.reason = f"malformed Mach-O — bounded parser refused: {exc}"
        report.limitations.append("structure parsing failed safely (§14)")
        return report


def _parse(data: bytes, report: MachOReport) -> MachOReport:
    if len(data) < 8:
        report.reason = "file too short for any Mach-O magic"
        return report
    magic = int.from_bytes(data[:4], "big")
    fat_endian = _FAT_MAGICS.get(magic)
    if fat_endian is not None and magic == 0xCAFEBABE:
        return _parse_fat(data, report)
    if magic not in _MACHO_MAGICS:
        # little-endian fat (0xBEBAFECA) or unknown
        little_magic = int.from_bytes(data[:4], "little")
        if little_magic == 0xCAFEBABE and magic != 0xCAFEBABE:
            return _parse_fat(data, report, endian="little")
        report.reason = "not a Mach-O file"
        return report
    kind, endian = _MACHO_MAGICS[magic]
    report.bitness = 64 if kind == "macho64" else 32
    report.endianness = endian
    big = endian == "big"

    def U(off: int, size: int) -> int:
        if off < 0 or off + size > len(data):
            raise IndexError(f"read of {size} bytes at {off} exceeds the file")
        return int.from_bytes(data[off:off + size], "big" if big else "little")

    cputype = U(4, 4)
    filetype = U(12, 4)
    ncmds = U(16, 4)
    report.architecture = _CPUTYPES.get(cputype, f"unrecognized(cputype=0x{cputype:x})")
    report.filetype = _FILETYPES.get(filetype, f"unrecognized(filetype={filetype})")
    if ncmds > _MAX_COMMANDS:
        report.reason = (f"load command count {ncmds} exceeds the bounded "
                         f"limit {_MAX_COMMANDS} — refused, not truncated")
        return report

    header_size = 32 if report.bitness == 64 else 28
    offset = header_size
    for _ in range(ncmds):
        cmd = U(offset, 4)
        cmdsize = U(offset + 4, 4)
        if cmdsize < 8 or offset + cmdsize > len(data):
            report.limitations.append(
                "a load command exceeds the file — remaining commands "
                "unknown, never guessed")
            break
        if cmd in (_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB, _LC_ID_DYLIB):
            name_off = U(offset + 8, 4)
            name_start = offset + name_off
            if 0 < name_off < cmdsize and name_start < len(data):
                end = data.find(b"\x00", name_start,
                                min(name_start + 512, len(data)))
                name = data[name_start:end if end != -1 else name_start + 512]
                lib = name.decode("utf-8", errors="replace")
                if cmd != _LC_ID_DYLIB and len(report.libraries) < _MAX_LIBS:
                    report.libraries.append(lib)
        elif cmd == _LC_UUID and cmdsize >= 24:
            report.uuid = data[offset + 8:offset + 24].hex()
        elif cmd == _LC_SYMTAB:
            symoff = U(offset + 8, 4)
            nsyms = U(offset + 12, 4)
            stroff = U(offset + 16, 4)
            strsize = U(offset + 20, 4)
            if nsyms > _MAX_SYMBOLS:
                report.limitations.append(
                    f"symbol count {nsyms} exceeds the bounded limit "
                    f"{_MAX_SYMBOLS} — listing truncated with its reason")
                nsyms = _MAX_SYMBOLS
            if stroff + strsize <= len(data):
                strtab = data[stroff:stroff + strsize]
                nlist_size = 12 if report.bitness == 32 else 16
                for i in range(nsyms):
                    entry = symoff + i * nlist_size
                    if entry + nlist_size > len(data):
                        break
                    n_strx = U(entry, 4)
                    if n_strx < len(strtab):
                        end = strtab.find(b"\x00", n_strx,
                                          min(n_strx + 512, len(strtab)))
                        name = strtab[n_strx:end if end != -1 else n_strx + 512]
                        if name:
                            report.symbols.append(
                                name.decode("utf-8", errors="replace"))
        elif cmd in (_LC_SEGMENT, _LC_SEGMENT_64):
            segname = data[offset + 8:offset + 24].split(b"\x00")[0].decode(
                "ascii", "replace")
            report.segments.append({"name": segname})
        offset += cmdsize

    report.valid = True
    report.reason = "Mach-O structure parsed within bounded reads"
    return report


def _parse_fat(data: bytes, report: MachOReport,
               endian: str = "big") -> MachOReport:
    big = endian == "big"

    def U(off: int, size: int) -> int:
        if off < 0 or off + size > len(data):
            raise IndexError(f"read of {size} bytes at {off} exceeds the file")
        return int.from_bytes(data[off:off + size], "big" if big else "little")

    nfat = U(4, 4)
    if nfat > _MAX_SLICES:
        report.reason = (f"fat binary holds {nfat} slices, above the bounded "
                         f"limit {_MAX_SLICES} — refused, not truncated")
        return report
    report.bitness = 0
    report.endianness = "big" if big else "little"
    for i in range(nfat):
        base = 8 + i * 20
        cputype = U(base, 4)
        offset = U(base + 8, 4)
        size = U(base + 12, 4)
        if offset + size > len(data):
            report.limitations.append(
                f"slice {i} points outside the file — unknown, never guessed")
            continue
        slice_report = parse_macho(data[offset:offset + size])
        report.slices.append({
            "architecture": _CPUTYPES.get(cputype, f"unrecognized(0x{cputype:x})"),
            "offset": offset, "size": size,
            "valid": slice_report.valid,
        })
        if slice_report.valid:
            report.libraries.extend(slice_report.libraries)
            report.symbols.extend(slice_report.symbols)
    report.valid = bool(report.slices)
    report.reason = ("universal/fat binary — slices inventoried within "
                     "bounded reads")
    report.architecture = "universal"
    report.filetype = "fat"
    return report
