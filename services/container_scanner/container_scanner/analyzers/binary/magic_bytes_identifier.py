"""Identify file type from magic bytes without spawning `file`."""

from __future__ import annotations

from pathlib import Path

MAGIC = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xca\xfe\xba\xbe", "mach-o-fat"),
    (b"\xcf\xfa\xed\xfe", "mach-o"),
    (b"PK\x03\x04", "zip"),
    (b"!<arch>\n", "ar"),
)


def identify_magic(path: Path) -> str | None:
    try:
        header = path.read_bytes()[:8]
    except OSError:
        return None
    for prefix, kind in MAGIC:
        if header.startswith(prefix):
            return kind
    return None


def is_binary(path: Path) -> bool:
    kind = identify_magic(path)
    return kind in {"elf", "pe", "mach-o", "mach-o-fat"}
