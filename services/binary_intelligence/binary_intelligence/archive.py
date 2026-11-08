"""Bounded static-archive (.a) analysis (§18 MVP: static libraries).

ar members are inventoried and ELF members parsed at depth 1 — a nested
archive inside a member is listed, never unpacked (§14). Boundaries:
member count and total bytes are bounded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from binary_intelligence.elf import parse_elf

_MAX_MEMBERS = 512
_MAX_TOTAL = 256 * 1024 * 1024


@dataclass
class ArchiveReport:
    valid: bool
    reason: str = ""
    members: List[Dict[str, Any]] = field(default_factory=list)
    imported_symbols: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid, "reason": self.reason,
            "members": self.members,
            "imported_symbols": self.imported_symbols[:200],
            "dependencies": self.dependencies,
            "limitations": self.limitations,
        }


def parse_archive(data: bytes) -> ArchiveReport:
    report = ArchiveReport(valid=False)
    if not data.startswith(b"!<arch>\n"):
        report.reason = "not an ar archive"
        return report
    pos = 8
    total = 0
    count = 0
    while pos + 60 <= len(data):
        if count >= _MAX_MEMBERS:
            report.reason = (f"member count exceeds the bounded limit "
                             f"{_MAX_MEMBERS} — refused, not truncated")
            return report
        header = data[pos:pos + 60]
        name = header[:16].decode("ascii", "replace").strip()
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            report.reason = f"member {name!r} carries a malformed size"
            return report
        total += size
        if total > _MAX_TOTAL:
            report.reason = ("archive total exceeds the bounded size limit "
                             "— refused (§14)")
            return report
        body_start = pos + 60
        body_end = body_start + size
        if body_end > len(data):
            report.limitations.append(
                f"member {name[:40]} extends past the file — unknown, "
                "never guessed")
            break
        member = data[body_start:body_end]
        entry: Dict[str, Any] = {"name": name.rstrip("/"), "size": size}
        if name.startswith("//") or name == "/":
            entry["kind"] = "symbol-index"
        elif member.startswith(b"\x7fELF"):
            elf = parse_elf(member)
            entry["kind"] = "elf"
            entry["valid"] = elf.valid
            report.imported_symbols.extend(elf.imported_symbols)
            report.dependencies.extend(elf.dynamic_dependencies)
        elif member[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                            b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            entry["kind"] = "macho"
        else:
            entry["kind"] = "data"
        report.members.append(entry)
        pos = body_end + (size % 2)    # members are 2-byte aligned
        count += 1
    report.valid = True
    report.reason = f"{count} members inventoried within bounded reads"
    return report
