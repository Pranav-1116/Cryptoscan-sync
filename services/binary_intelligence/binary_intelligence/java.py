"""Java class and JAR analysis (§1 Stage 1, §4 Stage 2, MVP scope).

A .class file is parsed from its constant pool — class names, method
references, interface references and string constants (cryptographic
transformation strings live there, e.g. 'AES/GCM/NoPadding'). A JAR is
a ZIP container: extraction is BOUNDED (§14) — entry count, per-entry
size, total uncompressed size and nesting depth are enforced, entries
are read in memory only (never written to disk), and a nested archive
is inventoried as a component, not recursively extracted.
"""

from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MAX_ENTRIES = 4096
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_CLASSES = 512
MAX_POOL_ENTRIES = 8192
MAX_STRING = 512

# constant pool tags
_UTF8, _INTEGER, _FLOAT, _LONG, _DOUBLE = 1, 3, 4, 5, 6
_CLASS, _STRING, _FIELDREF, _METHODREF = 7, 8, 9, 10
_IFACEMETHODREF, _NAMEANDTYPE = 11, 12


@dataclass
class ClassReport:
    class_name: str = ""
    super_name: str = ""
    interfaces: List[str] = field(default_factory=list)
    method_refs: List[str] = field(default_factory=list)
    field_refs: List[str] = field(default_factory=list)
    string_constants: List[str] = field(default_factory=list)
    class_refs: List[str] = field(default_factory=list)
    parse_status: str = "parsed"
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "class_name": self.class_name, "super_name": self.super_name,
            "interfaces": self.interfaces,
            "method_refs": self.method_refs[:200],
            "field_refs": self.field_refs[:200],
            "string_constants": self.string_constants[:200],
            "class_refs": self.class_refs[:200],
            "parse_status": self.parse_status,
            "limitations": self.limitations,
        }


@dataclass
class JarReport:
    valid: bool
    reason: str = ""
    manifest: Dict[str, str] = field(default_factory=dict)
    classes: List[ClassReport] = field(default_factory=list)
    embedded_archives: List[str] = field(default_factory=list)
    entries_total: int = 0
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid, "reason": self.reason,
            "manifest": self.manifest,
            "classes": [c.as_dict() for c in self.classes],
            "embedded_archives": self.embedded_archives,
            "entries_total": self.entries_total,
            "limitations": self.limitations,
        }


def parse_class(data: bytes) -> ClassReport:
    report = ClassReport()
    try:
        return _parse_class(data, report)
    except (IndexError, ValueError, struct.error) as exc:
        report.parse_status = "unparsable"
        report.limitations.append(
            f"class structure refused safely: {type(exc).__name__} — "
            "metadata is unknown, never guessed")
        return report


def _parse_class(data: bytes, report: ClassReport) -> ClassReport:
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        report.parse_status = "not-a-class"
        report.limitations.append("missing CAFEBABE magic")
        return report
    # minor_version u2, major_version u2 at 4..8
    constant_pool_count = struct.unpack(">H", data[8:10])[0]
    if constant_pool_count > MAX_POOL_ENTRIES:
        report.parse_status = "refused"
        report.limitations.append(
            f"constant pool count {constant_pool_count} exceeds the "
            f"bounded limit {MAX_POOL_ENTRIES} — refused, not truncated")
        return report

    strings: Dict[int, str] = {}
    class_refs: Dict[int, int] = {}
    pos = 10
    index = 1
    while index < constant_pool_count:
        tag = data[pos]
        pos += 1
        if tag == _UTF8:
            length = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 2
            strings[index] = data[pos:pos + length].decode(
                "utf-8", errors="replace")[:MAX_STRING]
            pos += length
        elif tag in (_INTEGER, _FLOAT):
            pos += 4
        elif tag in (_LONG, _DOUBLE):
            pos += 8
            index += 1          # long/double take two pool slots
        elif tag == _CLASS:
            class_refs[index] = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 2
        elif tag == _STRING:
            pos += 2
        elif tag in (_FIELDREF, _METHODREF, _IFACEMETHODREF, _NAMEANDTYPE):
            pos += 4
        else:
            report.limitations.append(
                f"unknown constant-pool tag {tag} at slot {index} — "
                "parsing stopped here; the rest is unknown, never guessed")
            report.parse_status = "partial"
            return report
        index += 1

    def utf8(slot: int) -> str:
        return strings.get(slot, "")

    def class_name(slot: int) -> str:
        return utf8(class_refs.get(slot, 0))

    # access_flags u2, this_class u2, super_class u2
    access_flags, this_class, super_class = struct.unpack(
        ">HHH", data[pos:pos + 6])
    pos += 6
    report.class_name = class_name(this_class)
    report.super_name = class_name(super_class)

    interfaces_count = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    for _ in range(min(interfaces_count, 256)):
        slot = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        name = class_name(slot)
        if name:
            report.interfaces.append(name)

    # fields + methods: access, name_idx, desc_idx, attributes (skipped)
    def skip_members(count: int) -> None:
        nonlocal pos
        for _ in range(count):
            _access, name_idx, desc_idx, attr_count = struct.unpack(
                ">HHHH", data[pos:pos + 8])
            pos += 8
            for _ in range(attr_count):
                _name, length = struct.unpack(">HI", data[pos:pos + 6])
                pos += 6 + length

    fields_count = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    skip_members(fields_count)
    methods_count = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    skip_members(methods_count)

    # derive references from the pool: method/field refs are (class, nat)
    for index, slot in class_refs.items():
        name = class_name(index)
        if name:
            report.class_refs.append(name)

    # rebuild method/field refs by re-walking the pool — we captured only
    # offsets, so re-parse quickly for the ref kinds
    pos2 = 10
    index = 1
    while index < constant_pool_count:
        tag = data[pos2]
        pos2 += 1
        if tag == _UTF8:
            length = struct.unpack(">H", data[pos2:pos2 + 2])[0]
            pos2 += 2 + length
        elif tag in (_INTEGER, _FLOAT):
            pos2 += 4
        elif tag in (_LONG, _DOUBLE):
            pos2 += 8
            index += 1
        elif tag in (_CLASS, _STRING):
            pos2 += 2
        elif tag in (_FIELDREF, _METHODREF, _IFACEMETHODREF):
            cls_idx, _nat_idx = struct.unpack(">HH", data[pos2:pos2 + 4])
            pos2 += 4
            owner = class_name(cls_idx)
            # The class owner is the available metadata for this reference.
            label = owner or "?"
            if tag == _METHODREF:
                report.method_refs.append(label)
            elif tag == _IFACEMETHODREF:
                report.method_refs.append(label)
            else:
                report.field_refs.append(label)
        elif tag == _NAMEANDTYPE:
            pos2 += 4
        else:
            break
        index += 1

    for value in strings.values():
        if value:
            report.string_constants.append(value)
    return report


def _nat_offset(data: bytes, index: int) -> Optional[int]:
    return None    # offsets are not retained; names resolved via strings


def parse_jar(data: bytes) -> JarReport:
    """Parse a JAR/WAR/EAR (ZIP container) with bounded extraction."""
    report = JarReport(valid=False)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        report.reason = f"not a readable ZIP container: {exc}"
        return report
    try:
        with zf:
            entries = zf.infolist()
            report.entries_total = len(entries)
            if len(entries) > MAX_ENTRIES:
                report.reason = (
                    f"archive holds {len(entries)} entries, above the "
                    f"bounded limit {MAX_ENTRIES} — refused as a potential "
                    "archive bomb (§14)")
                return report
            total = 0
            for entry in entries:
                if entry.file_size > MAX_ENTRY_BYTES:
                    report.reason = (
                        f"entry {entry.filename[:80]} expands to "
                        f"{entry.file_size} bytes, above the bounded limit "
                        f"{MAX_ENTRY_BYTES} — refused (§14)")
                    return report
                total += entry.file_size
                if total > MAX_TOTAL_BYTES:
                    report.reason = (
                        "archive total uncompressed size exceeds the "
                        "bounded limit — refused as a potential archive "
                        "bomb (§14)")
                    return report
            for entry in entries:
                name = entry.filename
                # path traversal defence: names are used in memory only,
                # but a traversal name is still refused
                if name.startswith("/") or ".." in name.split("/"):
                    report.limitations.append(
                        f"entry {name[:80]} carries a traversal-style name — "
                        "refused, never extracted")
                    continue
                if name == "META-INF/MANIFEST.MF":
                    text = zf.read(entry)[:64 * 1024].decode(
                        "utf-8", errors="replace")
                    for line in text.splitlines():
                        if ":" in line:
                            key, _, value = line.partition(":")
                            report.manifest[key.strip()] = value.strip()
                elif name.endswith(".class") and len(report.classes) < MAX_CLASSES:
                    blob = zf.read(entry)
                    class_report = parse_class(blob)
                    report.classes.append(class_report)
                elif name.endswith((".jar", ".war", ".ear")):
                    report.embedded_archives.append(name)
                    report.limitations.append(
                        f"embedded archive {name[:80]} inventoried as a "
                        "component — nested extraction depth is bounded at "
                        "0 here (§14); contents are not unpacked")
            report.valid = True
            report.reason = (
                f"{len(report.classes)} classes parsed within bounded reads")
            return report
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        report.reason = f"archive refused safely: {type(exc).__name__}"
        return report
