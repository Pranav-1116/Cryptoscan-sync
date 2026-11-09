"""Ground-truth binary test corpus (§15): samples we build ourselves,
so every expected finding is KNOWN. ``test_provenance`` is
'constructed-fixture' — synthetic samples, never real bank artifacts.
"""

from __future__ import annotations

from typing import Dict


def _elf64_le_x86_64(*, with_crypto: bool, stripped: bool) -> bytes:
    """A minimal but structurally real ELF64 LE x86-64 shared object:
    ELF header + section table + shstrtab + .dynstr + .dynamic (DT_NEEDED)
    + .dynsym with imported symbols + optional .comment."""
    import struct

    needed = [b"libcrypto.so.3"] if with_crypto else [b"libc.so.6"]
    imports = ([b"EVP_aes_256_gcm", b"RSA_generate_key_ex", b"EVP_sha256"]
               if with_crypto else [b"printf", b"malloc"])

    dynstr = b"\x00"
    needed_offs = []
    for name in needed:
        needed_offs.append(len(dynstr))
        dynstr += name + b"\x00"
    sym_name_offs = []
    for name in imports:
        sym_name_offs.append(len(dynstr))
        dynstr += name + b"\x00"

    # SHT_DYNSYM entries: st_name(4) st_info(1) st_other(1) st_shndx(2)
    # st_value(8) st_size(8) — undefined symbols (st_shndx=0) = imports
    dynsym = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)   # null entry
    for off in sym_name_offs:
        dynsym += struct.pack("<IBBHQQ", off, 0x12, 0, 0, 0, 0)

    # SHT_DYNAMIC entries: d_tag(8) d_val(8)
    dynamic = b""
    for off in needed_offs:
        dynamic += struct.pack("<QQ", 1, off)            # DT_NEEDED
    dynamic += struct.pack("<QQ", 5, 0)                  # DT_STRTAB
    dynamic += struct.pack("<QQ", 0, 0)                  # DT_NULL

    comment = b"GCC: (GNU) 11.4.0\x00" if with_crypto else b"\x00"
    shstrtab = b"\x00.dynstr\x00.dynsym\x00.dynamic\x00.comment\x00.shstrtab\x00"
    if not stripped:
        shstrtab += b".symtab\x00"

    names = {}
    pos = 0
    for part in shstrtab.split(b"\x00"):
        if part:
            names[part.decode()] = pos
        pos += len(part) + 1

    # layout: ehdr(64) | segments... | section headers
    ehdr_size = 64
    segments = [(dynstr, 8), (dynsym, 8), (dynamic, 8), (comment, 1),
                (shstrtab, 1)]
    if not stripped:
        segments.append((b"\x00" * 24, 8))   # fake .symtab (nonzero type)

    offsets = {}
    cursor = ehdr_size
    body = b""
    for content, _align in segments:
        body += content
        cursor += len(content)
    # rebuild with offsets
    body = b""
    cursor = ehdr_size
    ordered = []
    for content, align in segments:
        pad = (align - cursor % align) % align
        body += b"\x00" * pad
        cursor += pad
        ordered.append((content, cursor))
        body += content
        cursor += len(content)

    section_names = [".dynstr", ".dynsym", ".dynamic", ".comment"]
    shstrtab_off = None
    symtab_off = None
    for (content, off), name in zip(ordered, section_names):
        offsets[name] = off
    # remaining: shstrtab and optional symtab
    remaining = ordered[len(section_names):]
    shstrtab_off = remaining[0][1]
    if not stripped:
        symtab_off = remaining[1][1]

    shoff = cursor
    pad = (8 - shoff % 8) % 8
    body += b"\x00" * pad
    shoff += pad

    SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_DYNSYM = 1, 2, 3, 6, 11
    sections = [  # (name, type, flags, addr, offset, size)
        ("", 0, 0, 0, 0, 0),
        (".dynstr", SHT_STRTAB, 0x2, 0, offsets[".dynstr"], len(dynstr)),
        (".dynsym", SHT_DYNSYM, 0x2, 0, offsets[".dynsym"], len(dynsym)),
        (".dynamic", SHT_DYNAMIC, 0x3, 0, offsets[".dynamic"], len(dynamic)),
        (".comment", SHT_PROGBITS, 0, 0, offsets[".comment"], len(comment)),
        (".shstrtab", SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab)),
    ]
    if not stripped:
        sections.append((".symtab", SHT_SYMTAB, 0, 0, symtab_off, 24))

    shnum = len(sections)
    shstrndx = 5

    def shdr(name: str, sh_type: int, flags: int, addr: int,
             off: int, size: int) -> bytes:
        name_off = names.get(name, 0)
        return struct.pack("<IIQQQQIIQQ", name_off, sh_type, flags, addr,
                           off, size, 0, 0, 8 if sh_type in (SHT_SYMTAB, SHT_DYNSYM, SHT_DYNAMIC) else 1, 0)

    shdrs = b"".join(shdr(*s) for s in sections)

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2          # ELFCLASS64
    ehdr[5] = 1          # ELFDATA2LSB
    ehdr[6] = 1          # EV_CURRENT
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16,
                     3,          # e_type = ET_DYN (shared object)
                     0x3E,       # e_machine = x86-64
                     1,          # e_version
                     0x1000,     # e_entry
                     0,          # e_phoff
                     shoff,      # e_shoff
                     0,          # e_flags
                     64,         # e_ehsize
                     0,          # e_phentsize
                     0,          # e_phnum
                     64,         # e_shentsize
                     shnum,      # e_shnum
                     shstrndx)   # e_shstrndx
    return bytes(ehdr) + body + shdrs


def elf_crypto_sample() -> bytes:
    return _elf64_le_x86_64(with_crypto=True, stripped=True)


def elf_plain_sample() -> bytes:
    return _elf64_le_x86_64(with_crypto=False, stripped=False)


def _pe64_with_imports() -> bytes:
    """A minimal but structurally real PE32+ (x86-64) with an import
    table naming libcrypto-3-x64.dll and two crypto functions."""
    import struct

    # layout: DOS(0x80) | PE sig+COFF(24) | optional(240) | sections(2*40)
    # section .rdata at raw 0x260, VA 0x1000, size 0x400
    raw_off = 0x260
    va = 0x1000

    def rva(pos: int) -> int:
        return va + (pos - raw_off)

    rdata = bytearray(0x400)
    # import descriptor at pos 0x260 (rva 0x1000): one DLL + null
    # descriptor: OriginalFirstThunk, TimeDate, Forwarder, Name, FirstThunk
    ilt_off = 0x2A0
    dll_off = 0x2D0
    hint_off = 0x2F0
    hint2_off = 0x310
    struct.pack_into("<IIIII", rdata, 0, rva(ilt_off), 0, 0,
                     rva(dll_off), rva(ilt_off))
    struct.pack_into("<IIIII", rdata, 20, 0, 0, 0, 0, 0)
    rdata[dll_off - raw_off:dll_off - raw_off + 20] = b"libcrypto-3-x64.dll\x00"
    # ILT: two hint/name entries + null
    struct.pack_into("<QQQ", rdata, ilt_off - raw_off,
                     rva(hint_off), rva(hint2_off), 0)
    rdata[hint_off - raw_off:hint_off - raw_off + 2 + 16] = \
        struct.pack("<H", 0) + b"EVP_aes_256_gcm\x00"
    rdata[hint2_off - raw_off:hint2_off - raw_off + 2 + 18] = \
        struct.pack("<H", 0) + b"BCryptSignHash\x00"

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    pe = bytearray()
    pe += b"PE\x00\x00"
    # COFF header: machine x86-64, 1 section, opt size 240
    pe += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)        # PE32+
    struct.pack_into("<I", opt, 16, 0x1000)      # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)      # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)       # FileAlignment
    struct.pack_into("<H", opt, 48, 6)           # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, 0x2000)      # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x260)       # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)           # Subsystem console
    struct.pack_into("<I", opt, 108, 16)         # NumberOfRvaAndSizes
    # data directory[1] = import: rva 0x1000, size 40
    struct.pack_into("<II", opt, 112 + 8, 0x1000, 40)
    pe += opt
    # section .rdata
    sec = bytearray(40)
    sec[0:8] = b".rdata\x00\x00"
    struct.pack_into("<IIIIIIHHI", sec, 8, 0x400, va, 0x400,
                     raw_off, 0, 0, 0, 0, 0x40000040)
    pe += sec

    out = bytearray(raw_off)
    out[0:0x80] = dos
    out[0x80:0x80 + len(pe)] = pe
    out += rdata
    return bytes(out)


def pe_crypto_sample() -> bytes:
    return _pe64_with_imports()


def jar_like_sample() -> bytes:
    """A ZIP container (jar/war/apk are ZIP-based)."""
    return (b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00" * 60)


GROUND_TRUTH: Dict[str, Dict] = {
    "elf_crypto": {
        "test_provenance": "constructed-fixture",
        "file_format": "elf", "architecture": "x86-64",
        "known_components": ["libcrypto.so.3"],
        "known_crypto_algorithms": ["AES-256-GCM", "RSA", "SHA-256"],
        "expected_dependencies": ["libcrypto.so.3"],
        "expected_findings": ["AES", "RSA", "SHA-2"],
        "expected_non_findings": ["ML-KEM"],
    },
    "elf_plain": {
        "test_provenance": "constructed-fixture",
        "file_format": "elf", "architecture": "x86-64",
        "known_components": ["libc.so.6"],
        "known_crypto_algorithms": [],
        "expected_dependencies": ["libc.so.6"],
        "expected_findings": [],
        "expected_non_findings": ["AES", "RSA"],
    },
    "pe_crypto": {
        "test_provenance": "constructed-fixture",
        "file_format": "pe", "architecture": "x86-64",
        "known_components": ["libcrypto-3-x64.dll"],
        "known_crypto_algorithms": ["AES-256-GCM"],
        "expected_dependencies": ["libcrypto-3-x64.dll"],
        "expected_findings": ["AES"],
        "expected_non_findings": ["ML-DSA"],
    },
}
