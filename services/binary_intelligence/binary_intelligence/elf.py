"""Bounded ELF structural parser (§4 Stage 2, §14).

Parses headers, section headers, dynamic dependencies and dynamic
symbols WITHOUT executing anything and with bounded reads: every offset
is validated against the file length before access, and a malformed
field fails safe with its reason — a parser crash is a parser bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

#: ELF machine numbers we name. Anything else is "unrecognized", never
#: guessed into a familiar architecture.
_MACHINES = {
    0x02: "sparc", 0x03: "x86", 0x08: "mips", 0x14: "powerpc",
    0x15: "powerpc64", 0x16: "s390", 0x28: "arm", 0x2A: "superh",
    0x3E: "x86-64", 0xB7: "aarch64", 0xF3: "riscv",
}

_ETYPES = {1: "relocatable", 2: "executable", 3: "shared_object", 4: "core"}

DT_NEEDED = 1
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
_NULL = 0
_SYMTAB = 2
_STRTAB = 3
_DYNAMIC = 6
_NOTE = 7
_NOBITS = 8
_DYNSYM = 11
_MAX_ENTRIES = 4096
_MAX_SECTIONS = 512
_MAX_SYMBOLS = 8192
_MAX_STRING = 512


@dataclass
class ELFReport:
    valid: bool
    reason: str = ""
    bitness: int = 0
    endianness: str = ""
    architecture: str = ""
    elf_type: str = ""
    entry_point: int = 0
    sections: List[Dict[str, Any]] = field(default_factory=list)
    dynamic_dependencies: List[str] = field(default_factory=list)
    imported_symbols: List[str] = field(default_factory=list)
    exported_symbols: List[str] = field(default_factory=list)
    build_id: Optional[str] = None
    compiler: Optional[str] = None
    stripped: bool = False
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid, "reason": self.reason,
            "bitness": self.bitness, "endianness": self.endianness,
            "architecture": self.architecture, "elf_type": self.elf_type,
            "entry_point": self.entry_point, "sections": self.sections,
            "dynamic_dependencies": self.dynamic_dependencies,
            "imported_symbols": self.imported_symbols,
            "exported_symbols": self.exported_symbols,
            "build_id": self.build_id, "compiler": self.compiler,
            "stripped": self.stripped, "limitations": self.limitations,
        }


def _u(data: bytes, off: int, size: int, signed: bool = False) -> int:
    if off < 0 or off + size > len(data):
        raise IndexError(f"read of {size} bytes at {off} exceeds the file")
    return int.from_bytes(data[off:off + size], "little", signed=signed)


def _cstr(data: bytes, off: int) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, min(off + _MAX_STRING, len(data)))
    if end == -1:
        end = min(off + _MAX_STRING, len(data))
    return data[off:end].decode("utf-8", errors="replace")


def parse_elf(data: bytes) -> ELFReport:
    report = ELFReport(valid=False)
    try:
        return _parse(data, report)
    except (IndexError, ValueError, OverflowError) as exc:
        report.valid = False
        report.reason = f"malformed ELF — bounded parser refused: {exc}"
        report.limitations.append("structure parsing failed safely (§14)")
        return report


def _parse(data: bytes, report: ELFReport) -> ELFReport:
    if len(data) < 16 or not data.startswith(b"\x7fELF"):
        report.reason = "not an ELF file"
        return report
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        report.reason = f"unknown ELF class {ei_class}"
        return report
    if ei_data not in (1, 2):
        report.reason = f"unknown ELF data encoding {ei_data}"
        return report
    report.bitness = 32 if ei_class == 1 else 64
    report.endianness = "little" if ei_data == 1 else "big"
    big = ei_data == 2

    def U(off: int, size: int) -> int:
        if off < 0 or off + size > len(data):
            raise IndexError(f"read of {size} bytes at {off} exceeds the file")
        return int.from_bytes(data[off:off + size],
                             "big" if big else "little")

    e_type = U(16, 2)
    e_machine = U(18, 2)
    report.elf_type = _ETYPES.get(e_type, f"unrecognized(type={e_type})")
    report.architecture = _MACHINES.get(
        e_machine, f"unrecognized(machine={e_machine})")
    report.entry_point = U(24, 8 if ei_class == 2 else 4)

    if ei_class == 2:
        e_shoff, e_shentsize, e_shnum, e_shstrndx = U(40, 8), U(58, 2), U(60, 2), U(62, 2)
    else:
        e_shoff, e_shentsize, e_shnum, e_shstrndx = U(32, 4), U(46, 2), U(48, 2), U(50, 2)

    if e_shnum > _MAX_SECTIONS:
        report.reason = (f"section count {e_shnum} exceeds the bounded "
                         f"limit {_MAX_SECTIONS} — refused, not truncated")
        return report

    sections: List[Dict[str, Any]] = []
    shstrtab = b""
    raw_sections: List[Tuple[int, int, int, int, int, int]] = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if ei_class == 2:
            name_off, sh_type = U(base, 4), U(base + 4, 4)
            sh_flags, sh_addr = U(base + 8, 8), U(base + 16, 8)
            sh_offset, sh_size = U(base + 24, 8), U(base + 32, 8)
        else:
            name_off, sh_type = U(base, 4), U(base + 4, 4)
            sh_flags, sh_addr = U(base + 8, 4), U(base + 12, 4)
            sh_offset, sh_size = U(base + 16, 4), U(base + 20, 4)
        raw_sections.append((name_off, sh_type, sh_flags, sh_addr,
                             sh_offset, sh_size))
        if i == e_shstrndx and sh_type != _NOBITS:
            shstrtab = data[sh_offset:sh_offset + sh_size]

    symtab_present = False
    for name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size in raw_sections:
        name = _cstr(shstrtab, name_off) if shstrtab else ""
        sections.append({
            "name": name, "type": sh_type, "flags": sh_flags,
            "address": sh_addr, "offset": sh_offset, "size": sh_size,
            "executable": bool(sh_flags & 0x4),
        })
        if sh_type == _SYMTAB:
            symtab_present = True

    report.sections = sections
    report.stripped = not symtab_present
    if not symtab_present:
        report.limitations.append(
            "symbols were stripped — detection relies on dynamic symbols, "
            "imports and strings; absence of a finding is not proof of "
            "absence")

    # walk SHT_DYNAMIC for DT_NEEDED / DT_SONAME
    dyn_off = dyn_size = 0
    dynstr = b""
    for idx, (name_off, sh_type, _f, _a, sh_offset, sh_size) in enumerate(raw_sections):
        if sh_type == _DYNAMIC:
            dyn_off, dyn_size = sh_offset, sh_size
        if name_off < len(shstrtab) and _cstr(shstrtab, name_off) == ".dynstr" and sh_type != _NOBITS:
            dynstr = data[sh_offset:sh_offset + sh_size]

    entry_size = 16 if ei_class == 2 else 8
    needed: List[str] = []
    soname = None
    if dyn_off:
        for i in range(min(dyn_size // entry_size, _MAX_ENTRIES)):
            base = dyn_off + i * entry_size
            tag = U(base, 8 if ei_class == 2 else 4)
            val = U(base + 8 if ei_class == 2 else base + 4,
                    8 if ei_class == 2 else 4)
            if tag == _NULL:
                break
            if tag == DT_NEEDED:
                needed.append(_cstr(dynstr, val))
            elif tag == DT_SONAME:
                soname = _cstr(dynstr, val)
    report.dynamic_dependencies = [n for n in needed if n]
    if soname:
        report.limitations.append(f"soname={soname}")

    # dynamic symbols: undefined = imported, defined in dynsym = exported
    for name_off, sh_type, _f, _a, sh_offset, sh_size in raw_sections:
        if sh_type not in (_DYNSYM, _SYMTAB):
            continue
        entsize = 24 if ei_class == 2 else 16
        strtab = b""
        # matching SHT_STRTAB for this symtab is conventionally the next
        # section; instead resolve names against .dynstr then shstrtab
        count = min(sh_size // entsize, _MAX_SYMBOLS)
        for i in range(count):
            base = sh_offset + i * entsize
            st_name = U(base, 4)
            st_info = U(base + 4, 1)
            st_shndx = U(base + (6 if ei_class == 2 else 14), 2)
            name = _cstr(dynstr, st_name) or _cstr(shstrtab, st_name)
            if not name:
                continue
            bind = st_info >> 4
            if st_shndx == 0:
                report.imported_symbols.append(name)
            elif bind in (1, 2):
                report.exported_symbols.append(name)

    # build-id + compiler (.note and .comment sections)
    for name_off, sh_type, _f, _a, sh_offset, sh_size in raw_sections:
        name = _cstr(shstrtab, name_off) if shstrtab else ""
        if name == ".comment" and sh_type != _NOBITS and sh_size:
            report.compiler = _cstr(data, sh_offset) or None
        if sh_type == _NOTE and sh_size and sh_offset + sh_size <= len(data):
            note = data[sh_offset:sh_offset + sh_size]
            idx = 0
            while idx + 12 <= len(note):
                n_namesz = int.from_bytes(note[idx:idx + 4], "big" if big else "little")
                n_descsz = int.from_bytes(note[idx + 4:idx + 8], "big" if big else "little")
                n_type = int.from_bytes(note[idx + 8:idx + 12], "big" if big else "little")
                name_start = idx + 12
                desc_start = name_start + ((n_namesz + 3) & ~3)
                next_start = desc_start + ((n_descsz + 3) & ~3)
                if next_start > len(note) or n_descsz > 256:
                    break
                note_name = note[name_start:name_start + max(n_namesz - 1, 0)]
                if note_name == b"GNU" and n_type == 3 and n_descsz:
                    report.build_id = note[desc_start:desc_start + n_descsz].hex()
                idx = next_start

    report.valid = True
    report.reason = "ELF structure parsed within bounded reads"
    return report
