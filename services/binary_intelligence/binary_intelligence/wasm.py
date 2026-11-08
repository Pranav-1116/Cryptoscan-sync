"""Bounded WebAssembly module analysis (§17 Phase 4).

Sections are inventoried within bounded reads; IMPORT names feed crypto
detection (wasi_crypto, crypto.subtle style interfaces) as indicators —
never as proof of runtime use (§5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_MAX_SECTIONS = 256
_MAX_IMPORTS = 2048
_MAX_NAME = 256

_SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}


@dataclass
class WasmReport:
    valid: bool
    reason: str = ""
    version: int = 0
    sections: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid, "reason": self.reason,
            "version": self.version, "sections": self.sections,
            "imports": self.imports[:200], "exports": self.exports[:200],
            "limitations": self.limitations,
        }


def _read_leb(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    for _ in range(5):
        if pos >= len(data):
            raise IndexError("LEB128 exceeds the file")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
    raise ValueError("LEB128 too long")


def parse_wasm(data: bytes) -> WasmReport:
    report = WasmReport(valid=False)
    try:
        return _parse(data, report)
    except (IndexError, ValueError, OverflowError) as exc:
        report.reason = f"malformed WASM — refused safely: {exc}"
        report.limitations.append("structure parsing failed safely (§14)")
        return report


def _parse(data: bytes, report: WasmReport) -> WasmReport:
    if len(data) < 8 or data[:4] != b"\x00asm":
        report.reason = "not a WebAssembly module"
        return report
    report.version = int.from_bytes(data[4:8], "little")
    pos = 8
    count = 0
    while pos < len(data):
        if count >= _MAX_SECTIONS:
            report.reason = (f"section count exceeds the bounded limit "
                             f"{_MAX_SECTIONS} — refused, not truncated")
            return report
        section_id = data[pos]
        pos += 1
        size, pos = _read_leb(data, pos)
        if pos + size > len(data):
            report.limitations.append(
                f"section {_SECTION_NAMES.get(section_id, section_id)} "
                "extends past the file — remainder unknown, never guessed")
            break
        body = data[pos:pos + size]
        report.sections.append({
            "name": _SECTION_NAMES.get(section_id, f"unknown({section_id})"),
            "size": size,
        })
        if section_id == 2:      # import section
            cursor = 0
            try:
                n_imports, cursor = _read_leb(body, cursor)
            except (IndexError, ValueError):
                n_imports = 0
                report.limitations.append(
                    "import section count is malformed — imports unknown, "
                    "never guessed")
            for _ in range(min(n_imports, _MAX_IMPORTS)):
                try:
                    mlen, cursor = _read_leb(body, cursor)
                    module = body[cursor:cursor + mlen].decode(
                        "utf-8", errors="replace")
                    cursor += mlen
                    nlen, cursor = _read_leb(body, cursor)
                    name = body[cursor:cursor + nlen].decode(
                        "utf-8", errors="replace")
                    cursor += nlen
                    cursor += 1    # import kind
                    if cursor > len(body):
                        break
                    if len(name) <= _MAX_NAME:
                        report.imports.append(f"{module}.{name}")
                except (IndexError, ValueError):
                    report.limitations.append(
                        "import entries truncated — unknown, never guessed")
                    break
        elif section_id == 7:    # export section
            cursor = 0
            try:
                n_exports, cursor = _read_leb(body, cursor)
                for _ in range(min(n_exports, _MAX_IMPORTS)):
                    nlen, cursor = _read_leb(body, cursor)
                    name = body[cursor:cursor + nlen].decode(
                        "utf-8", errors="replace")
                    cursor += nlen + 1
                    if cursor > len(body):
                        break
                    report.exports.append(name[:_MAX_NAME])
            except (IndexError, ValueError):
                pass
        pos += size
        count += 1
    report.valid = True
    report.reason = "WASM sections parsed within bounded reads"
    return report
