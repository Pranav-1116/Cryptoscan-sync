"""Binary format identification from file CONTENT (§1: "a file extension
is only a hint"). A renamed or misleadingly named file is identified by
its magic bytes and structure — never by its name.
"""

from __future__ import annotations

from enum import Enum
from typing import Tuple


class BinaryFormat(str, Enum):
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    MACHO_FAT = "macho-fat"
    JAVA_CLASS = "java-class"
    ZIP_ARCHIVE = "zip-archive"          # .jar / .apk / .war are ZIP-based
    WASM = "wasm"
    STATIC_ARCHIVE = "static-archive"    # ar archive (.a)
    UNKNOWN = "unknown"


ELF_MAGIC = b"\x7fELF"
JAVA_CLASS_MAGIC = b"\xca\xfe\xba\xbe"
WASM_MAGIC = b"\x00asm"
ZIP_MAGIC = b"PK\x03\x04"
AR_MAGIC = b"!<arch>\n"

# Mach-O magic values (32/64, both endiannesses) and fat-binary magic.
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
}
_MACHO_FAT_MAGICS = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}


def identify_format(data: bytes) -> Tuple[BinaryFormat, str]:
    """Identify the format from content. Returns (format, reason).
    A format is UNKNOWN with its reason rather than guessed."""
    if len(data) < 4:
        return BinaryFormat.UNKNOWN, (
            "file is shorter than any known magic — content, not the "
            "extension, decides identity")
    head = data[:4]
    if data.startswith(ELF_MAGIC):
        klass = data[4] if len(data) > 4 else 0
        bit = {1: "ELF32", 2: "ELF64"}.get(klass, "ELF?")
        return BinaryFormat.ELF, f"{bit} identified by the ELF magic"
    if data.startswith(JAVA_CLASS_MAGIC) and head not in _MACHO_FAT_MAGICS:
        return BinaryFormat.JAVA_CLASS, "CAFEBABE class-file magic"
    if head in _MACHO_FAT_MAGICS:
        return BinaryFormat.MACHO_FAT, "fat/universal Mach-O magic"
    if head in _MACHO_MAGICS:
        return BinaryFormat.MACHO, "Mach-O magic"
    if data.startswith(WASM_MAGIC):
        return BinaryFormat.WASM, "WebAssembly magic + version"
    if data.startswith(AR_MAGIC):
        return BinaryFormat.STATIC_ARCHIVE, "ar archive magic"
    if data.startswith(ZIP_MAGIC):
        return BinaryFormat.ZIP_ARCHIVE, (
            "ZIP container magic — jar/apk/war are ZIP-based; contents "
            "decide what it holds")
    if data[:2] == b"MZ":
        return _identify_pe(data)
    return BinaryFormat.UNKNOWN, (
        "no known magic matched — content, not the extension, decides "
        "identity; unknown is named, never guessed")


def _identify_pe(data: bytes) -> Tuple[BinaryFormat, str]:
    """MZ is only the DOS stub; the PE signature at e_lfanew confirms."""
    if len(data) < 0x40:
        return BinaryFormat.UNKNOWN, "MZ stub too short to hold a PE header"
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew + 4 > len(data) or e_lfanew < 0x40:
        return BinaryFormat.UNKNOWN, (
            "MZ stub points outside the file — malformed, not PE")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return BinaryFormat.UNKNOWN, (
            "MZ without a PE signature — a DOS stub alone is not a PE")
    return BinaryFormat.PE, "MZ stub + PE signature at e_lfanew"
