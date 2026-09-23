"""Binary/firmware scanner: real parsers, graded evidence, honest gaps.

Fixtures are assembled byte by byte (ELF/PE/ar/zip/firmware) so the parsers are
exercised against structures they were written for, not against whatever
happens to be installed on the build machine. Nothing here needs a compiler.
"""
from __future__ import annotations

import gzip
import struct
import zipfile

import pytest

from devsecops import binary_scan as bs
from devsecops import crypto_constants as cc


# --------------------------------------------------------------- builders --- #
def _elf64(*, e_type: int = 3, machine: int = 0x3E, deps=(), soname: str | None = None,
           runpath: str | None = None, comment: bytes | None = None, build_id: bytes | None = None,
           imports=(), exports=(), strings=(), go_section: bytes | None = None,
           dynamic_extra=(), symbol_versions: dict | None = None,
           segments: tuple = (), constants: bytes = b"") -> bytes:
    """Assemble a real ELF64 with dynamic/symbol/comment/note sections."""
    dynstr = bytearray(b"\x00")
    offsets: dict[str, int] = {}

    def _intern(text: str) -> int:
        if text in offsets:
            return offsets[text]
        offsets[text] = len(dynstr)
        dynstr.extend(text.encode() + b"\x00")
        return offsets[text]

    version_r = b""
    if symbol_versions:
        version_r = _elf_version_needs(symbol_versions, _intern)
    dynamic: list[tuple[int, int]] = []
    for dep in deps:
        dynamic.append((1, _intern(dep)))
    if soname:
        dynamic.append((14, _intern(soname)))
    if runpath:
        dynamic.append((29, _intern(runpath)))
    dynamic.extend(tuple(dynamic_extra))
    dynamic.append((0, 0))

    symtab = bytearray()
    for offset, shndx in ((_intern(name), 0) for name in imports):
        symtab.extend(struct.pack("<IBBHQQ", offset, (1 << 4) | 2, 0, shndx, 0, 0))
    for offset in (_intern(name) for name in exports):
        symtab.extend(struct.pack("<IBBHQQ", offset, (1 << 4) | 2, 0, 1, 0, 0))

    dynamic_bytes = b"".join(struct.pack("<qQ", tag, value) for tag, value in dynamic)
    text = b"\x90" * 16
    sections: list[tuple[str, int, bytes, int, int]] = [
        ("", 0, b"", 0, 0),
        (".text", 1, text, 0, 0),
        (".dynstr", 3, bytes(dynstr), 0, 0),
        (".dynsym", 11, bytes(symtab), 2, 24),          # sh_link -> .dynstr
        (".dynamic", 6, dynamic_bytes, 2, 16),
    ]
    if comment is not None:
        sections.append((".comment", 1, comment, 0, 1))
    if build_id is not None:
        name = b"GNU\x00"
        descriptor = build_id + bytes((4 - len(build_id) % 4) % 4)
        note = struct.pack("<III", len(name), len(build_id), 3) + name + descriptor
        sections.append((".note.gnu.build-id", 7, note, 0, 0))
    if go_section is not None:
        sections.append((".go.buildinfo", 1, go_section, 0, 1))
    if version_r:
        sections.append((".gnu.version_r", 0x6FFFFFFE, version_r, 2, 0))
    if constants:
        sections.append((".rodata", 1, constants, 0, 0))
    # .data before .shstrtab so e_shstrndx stays the last section index
    sections.append((".data", 1, b"".join(s.encode() + b"\x00" for s in strings), 0, 0))
    sections.append((".shstrtab", 3, b"", 0, 0))

    shstr = bytearray(b"\x00")
    name_offsets: list[int] = []
    for name, _type, _data, _link, _entsize in sections:
        if not name:
            name_offsets.append(0)
            continue
        name_offsets.append(len(shstr))
        shstr.extend(name.encode() + b"\x00")
    sections[-1] = (".shstrtab", 3, bytes(shstr), 0, 0)

    body = bytearray()
    layout_offsets: list[int] = []
    cursor = 64
    file_sections: list[tuple[str, int, bytes, int, int, int]] = []
    for name, stype, data, link, entsize in sections:
        layout_offsets.append(cursor if data else 0)
        file_sections.append((name, stype, bytes(data), link, entsize, cursor if data else 0))
        body.extend(data)
        cursor += len(data)
        while cursor % 8:
            body.append(0)
            cursor += 1

    phoff = 0
    phnum = 0
    if segments:
        phoff = cursor
        phnum = len(segments)
        body.extend(b"\x00" * (phnum * 56))          # program header table, patched below
        cursor += phnum * 56
        placements: list[int] = []
        for _seg_type, _flags, _vaddr, payload in segments:
            while cursor % 8:
                body.append(0)
                cursor += 1
            placements.append(cursor)
            body.extend(payload)
            cursor += len(payload)
        # `body` starts at file offset 64 (the ELF header is prepended), so the
        # program header table is patched at its file offset minus that header
        for index, (seg_type, flags, vaddr, payload) in enumerate(segments):
            struct.pack_into("<IIQQQQQQ", body, phoff - 64 + index * 56, seg_type, flags,
                             placements[index], vaddr, vaddr, len(payload), len(payload), 0x1000)
    shoff = cursor
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01\x00" + bytes(8), e_type,
                         machine, 1, 0, phoff, shoff, 0, 64, 56 if phnum else 0, phnum, 64,
                         len(file_sections), len(file_sections) - 1)
    section_headers = b""
    for index, (name, stype, data, link, entsize, offset) in enumerate(file_sections):
        section_headers += struct.pack("<IIQQQQIIQQ", name_offsets[index], stype, 0, 0, offset,
                                       len(data), link, 0, 0x1000 if index == 1 else 0, entsize)
    return header + bytes(body) + section_headers


def _elf_version_needs(symbol_versions: dict, intern) -> bytes:
    """Build a .gnu.version_r (verneed/vernaux) block for the given library map."""
    needs: list[bytes] = []
    for library, versions in symbol_versions.items():
        aux = b""
        for index, version in enumerate(versions):
            last = index == len(versions) - 1
            aux += struct.pack("<IHHII", 0, 0, index + 2, intern(version), 16 if not last else 0)
        file_offset = intern(library)
        needs.append(struct.pack("<HHIII", 1, len(versions), file_offset, 16, 0) + aux)
    blob = b""
    for index, need in enumerate(needs):
        if index < len(needs) - 1:
            need = need[:12] + struct.pack("<I", 16 + 16 * len(symbol_versions[
                list(symbol_versions)[index]])) + need[16:]
        blob += need
    return blob


def _go_section(module: str, version: str, deps, toolchain: str = "go1.21.5") -> bytes:
    lines = [f"go\t{toolchain}", f"path\t{module}", f"mod\t{module}\t{version}\t"]
    lines += [f"dep\t{path}\t{ver}\th1:deadbeefcafe=" for path, ver in deps]
    blob = ("\n".join(lines) + "\n").encode()
    header = b"\xff\xff\xff\xf1" + toolchain.encode().ljust(18, b"\x00") + bytes([8] + [0] * 9)
    return header + blob + b"\x00\x00"


def _pe(*, machine: int = 0x8664, imports=("KERNEL32.dll",), dotnet: bool = False) -> bytes:
    """Minimal but structurally valid PE32+ with an import directory."""
    optional = 0x98
    section_table = optional + 240
    raw_offset = 0x400
    # allocate the whole file up front: writing past the end of a bytearray with
    # a slice assignment appends instead of padding, which would silently move
    # every RVA target
    data = bytearray(b"\x00" * (raw_offset + 0x200))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0x5F5E1000, 0, 0, 240, 0x0022)
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<H", data, optional + 68, 3)                       # console subsystem
    struct.pack_into("<I", data, optional + 108, 16)                     # number of directories
    if dotnet:
        struct.pack_into("<II", data, optional + 112 + 14 * 8, 0x1200, 0x48)   # CLR directory
    struct.pack_into("<II", data, optional + 112 + 1 * 8, 0x1000, 0x28)       # import directory
    data[section_table:section_table + 8] = b".rdata\x00\x00"
    # Name(8) VirtualSize(4) VirtualAddress(4) SizeOfRawData(4) PointerToRawData(4)
    struct.pack_into("<IIII", data, section_table + 8, 0x200, 0x1000, 0x200, raw_offset)
    descriptors = b""
    for offset, dll in enumerate(imports):
        name_rva = 0x1040 + sum(len(item) + 1 for item in imports[:offset])
        descriptors += struct.pack("<IIIII", 0, 0, 0, name_rva, 0x1080)
    descriptors += b"\x00" * 20
    data[raw_offset:raw_offset + len(descriptors)] = descriptors
    blob = b"".join(dll.encode() + b"\x00" for dll in imports)
    data[raw_offset + 0x40:raw_offset + 0x40 + len(blob)] = blob
    return bytes(data)


def _version_info_blob(version: str = "9.1.0.0", product: str = "Acme Toolkit") -> bytes:
    """VS_VERSIONINFO with a fixed file info block and StringFileInfo entries."""

    def _utf16(text: str) -> bytes:
        return text.encode("utf-16-le") + b"\x00\x00"

    def _pad4(value: bytes) -> bytes:
        return value + b"\x00" * ((4 - len(value) % 4) % 4)

    def _block(key: str, value_length: int, value: bytes = b"", children: bytes = b"",
               value_type: int = 1) -> bytes:
        raw = struct.pack("<HHH", 0, value_length, value_type) + _utf16(key)
        raw = _pad4(raw) + value
        raw = _pad4(raw) + children
        raw = _pad4(raw)
        return struct.pack("<H", len(raw)) + raw[2:]

    fixed = struct.pack("<13I", 0xFEEF04BD, 0x00010000, (9 << 16) | 1, 0, (9 << 16) | 1, 0,
                        0x3F, 0, 4, 1, 0, 0, 0)
    entries = b""
    for key, value in (("CompanyName", "Acme Corp"), ("ProductName", product),
                       ("FileVersion", version), ("OriginalFilename", "acme.exe"),
                       ("LegalCopyright", "Copyright Acme")):
        entries += _block(key, len(value) + 1, _utf16(value))
    table = _block("040904b0", 0, b"", entries)
    strings = _block("StringFileInfo", 0, b"", table)
    var = _block("VarFileInfo", 0, b"", _block("Translation", 4, struct.pack("<HH", 0x409, 1200)))
    return _block("VS_VERSION_INFO", len(fixed), fixed, strings + var, value_type=0)


def _pe_rich(*, constants: bytes = b"", delay_dll: str = "CRYPT32.dll", signed: bool = True,
             pdb: str = "C:\\build\\acme\\acme.pdb", subsystem: int = 3,
             clr: bool = False, dll_characteristics: int = 0x4160,
             load_config: bool = False, security_cookie: int = 0x140002000,
             guard_flags: int = 0x100) -> bytes:
    """PE32+ with version resources, debug dir, delay imports, cert table, Rich."""
    raw_offset = 0x400
    pe_offset = 0x100
    rdata = bytearray(0x1000)
    data = bytearray(raw_offset + 0x1000)

    # .rdata, RVA 0x1000 (== file offset 0x400): imports, delay imports, debug,
    # certificate, resource tree, version blob
    struct.pack_into("<IIIII", rdata, 0x00, 0, 0, 0, 0x1040, 0)
    rdata[0x40:0x40 + 13] = b"KERNEL32.dll\x00"
    struct.pack_into("<II", rdata, 0x100, 1, 0x1140)          # delay descriptor
    rdata[0x140:0x140 + len(delay_dll) + 1] = delay_dll.encode() + b"\x00"
    rsds = (b"RSDS" + bytes.fromhex("00112233445566778899aabbccddeeff")
            + struct.pack("<I", 3) + pdb.encode() + b"\x00")
    rdata[0x200:0x200 + len(rsds)] = rsds
    struct.pack_into("<IIHHIIII", rdata, 0x180, 0, 0, 0, 0, 2, len(rsds), 0x1200, 0x600)
    certificate = struct.pack("<IHH", 0x120, 0x200, 2) + b"\x30\x82fake-pkcs7-signature"
    cert_offset = raw_offset + 0x280
    rdata[0x280:0x280 + len(certificate)] = certificate

    def _directory(entries: list[tuple[int, int]]) -> bytes:
        header = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries))
        return header + b"".join(struct.pack("<II", name, child) for name, child in entries)

    # resource tree: root (types) -> name -> language -> data entry. The three
    # directory levels are all there is; the fourth hop is the data entry itself.
    version = _version_info_blob()
    rdata[0x500:0x500 + len(version)] = version
    struct.pack_into("<IIII", rdata, 0x360, 0x1500, len(version), 1200, 0)   # data entry
    rdata[0x340:0x340 + 24] = _directory([(0x409, 0x60)])                    # language
    rdata[0x320:0x320 + 24] = _directory([(1, 0x80000000 | 0x40)])           # name
    rdata[0x300:0x300 + 24] = _directory([(16, 0x80000000 | 0x20)])          # type = root

    if clr:
        version = b"v4.0.30319\x00\x00"
        metadata = (b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", len(version))
                    + version + bytes(4 - len(version) % 4) + b"\x00\x00\x00\x00")
        rdata[0x800:0x800 + 72] = struct.pack("<IHHIIII", 72, 2, 5, 0x1840, len(metadata),
                                              1, 0) + bytes(72 - 28)
        rdata[0x840:0x840 + len(metadata)] = metadata
    # a real constant table planted where a compiler would leave one
    rdata[0xC00:0xC00 + len(constants)] = constants
    data[raw_offset:raw_offset + 0x1000] = rdata

    # headers: DOS stub, Rich header at 0x80, PE signature at 0x100
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    key = 0x536E6144
    pairs = struct.pack("<II", 5 ^ key, ((0x10B << 16) | 0x2E07) ^ key)
    rich_block = b"DanS" + struct.pack("<III", key, key, key) + pairs + b"Rich" + struct.pack("<I", key)
    data[0x80:0x80 + len(rich_block)] = rich_block
    data[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, pe_offset + 4, 0x8664, 1, 0x5F5E1000, 0, 0, 240, 0x0022)
    optional = pe_offset + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<H", data, optional + 68, subsystem)
    struct.pack_into("<H", data, optional + 70, dll_characteristics)
    if load_config:
        # IMAGE_LOAD_CONFIG_DIRECTORY64: security cookie at 0x40, guard flags at 0x70
        config = bytearray(0x80)
        struct.pack_into("<I", config, 0, len(config))
        struct.pack_into("<Q", config, 0x40, security_cookie)
        struct.pack_into("<Q", config, 0x58, 0x140003000)          # SafeSEH table
        struct.pack_into("<I", config, 0x70, guard_flags)
        data[raw_offset + 0x700:raw_offset + 0x700 + len(config)] = config
    struct.pack_into("<I", data, optional + 108, 16)
    base = optional + 112
    struct.pack_into("<II", data, base + 1 * 8, 0x1000, 0x28)      # imports
    struct.pack_into("<II", data, base + 2 * 8, 0x1300, 0x180)     # resources
    struct.pack_into("<II", data, base + 4 * 8, cert_offset if signed else 0,
                     len(certificate) if signed else 0)            # certificate table
    struct.pack_into("<II", data, base + 6 * 8, 0x1180, 28)        # debug
    struct.pack_into("<II", data, base + 13 * 8, 0x1100, 0x60)     # delay imports
    if load_config:
        struct.pack_into("<II", data, base + 10 * 8, 0x1700, 0x80)  # load config
    if clr:
        struct.pack_into("<II", data, base + 14 * 8, 0x1800, 72)   # COM descriptor
    section_table = optional + 240
    data[section_table:section_table + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", data, section_table + 8, 0x1000, 0x1000, 0x1000, raw_offset)
    return bytes(data)


def _uimage(*, payload: bytes | None = None, name: str = "Acme Linux-6.1.38",
            os_id: int = 5, arch_id: int = 22, type_id: int = 3, comp_id: int = 1,
            stamp: int = 1780000000, data_crc: int | None = None,
            break_header_crc: bool = False, declare_size: int | None = None) -> bytes:
    """Legacy uImage with a real header CRC (and options to break each one)."""
    import zlib

    if payload is None:
        payload = _cpio([("lib/libacme.so", _elf64(soname="libacme.so.1"))])
    size = len(payload) if declare_size is None else declare_size
    if data_crc is None:
        data_crc = zlib.crc32(payload) & 0xFFFFFFFF
    header = bytearray(struct.pack(">7I4B32s", 0x27051956, 0, stamp, size, 0x80008000, 0x80008000,
                                   data_crc, os_id, arch_id, type_id, comp_id,
                                   name.encode()[:31].ljust(32, b"\x00")))
    hcrc = zlib.crc32(bytes(header)) & 0xFFFFFFFF
    struct.pack_into(">I", header, 4, (hcrc ^ 0xFFFF) if break_header_crc else hcrc)
    return bytes(header) + payload


def _macho(*, encrypted: bool = False, signed: bool = True, hardened: bool = True,
           flags: int = 0x200000, constants: bytes = b"") -> bytes:
    """Mach-O 64 (arm64) with dylib versions, symbols, build version, signature."""
    def _v(text: str, width: int) -> bytes:
        raw = text.encode() + b"\x00"
        return raw + b"\x00" * (width - len(raw))

    def _u32_version(value: str) -> int:
        major, minor, patch = (int(part) for part in (value.split(".") + ["0", "0"])[:3])
        return (major << 16) | (minor << 8) | patch

    strtab = bytearray(b"\x00")
    sym_offsets: dict[str, int] = {}

    def _intern(text: str) -> int:
        sym_offsets[text] = len(strtab)
        strtab.extend(text.encode() + b"\x00")
        return sym_offsets[text]

    _intern("_EVP_EncryptInit_ex")     # defined (statically linked OpenSSL)
    _intern("_CC_SHA256")              # defined (statically linked CommonCrypto)
    _intern("_CCCryptorCreate")        # undefined (CommonCrypto)
    _intern("_SecKeyEncrypt")          # undefined (Security.framework)
    nlist = (struct.pack("<IBBHQ", sym_offsets["_EVP_EncryptInit_ex"], 0x0F, 1, 0, 0x1000)
             + struct.pack("<IBBHQ", sym_offsets["_CC_SHA256"], 0x0F, 1, 0, 0x1008)
             + struct.pack("<IBBHQ", sym_offsets["_CCCryptorCreate"], 0x01, 0, 0, 0)
             + struct.pack("<IBBHQ", sym_offsets["_SecKeyEncrypt"], 0x01, 0, 0, 0))

    def _name16(text: str) -> bytes:
        raw = text.encode() + b"\x00"
        return raw + b"\x00" * (16 - len(raw))

    def _seg(section_offset: int = 0x200, section_size: int = 0x40) -> bytes:
        # section_64 is 80 bytes: names are 16 bytes each, including the NUL
        sect = (_name16("__text") + _name16("__TEXT")
                + struct.pack("<QQIIIIIII", 0x1000, section_size, section_offset, 4, 0, 0,
                              0x80000400, 0, 0))
        body = (_name16("__TEXT") + struct.pack("<QQQQIIII", 0x100000000, 0x2000, 0x200, 0x2000,
                5, 5, 1, 0) + sect)
        return struct.pack("<II", 0x19, 8 + len(body)) + body

    def _dylib(name: str, current: str, compat: str = "3.0.0", cmd: int = 0x0C) -> bytes:
        name_offset = 24
        body = struct.pack("<IIII", name_offset, 2, _u32_version(current),
                          _u32_version(compat)) + name.encode() + b"\x00"
        body += b"\x00" * ((8 - len(body) % 8) % 8)
        return struct.pack("<II", cmd, 8 + len(body)) + body

    def _cmd(cmd: int, payload: bytes) -> bytes:
        body = payload + b"\x00" * ((8 - (8 + len(payload)) % 8) % 8)
        return struct.pack("<II", cmd, 8 + len(body)) + body

    uuid = _cmd(0x1B, bytes.fromhex("aabbccddeeff00112233445566778899"))
    rpath = _cmd(0x1C, struct.pack("<I", 12) + b"@executable_path/../Frameworks\x00")
    build = _cmd(0x32, struct.pack("<IIII", 1, (13 << 16) | 1, (14 << 16) | 4, 0))
    main = _cmd(0x80000028, struct.pack("<QQ", 0x1000, 0))

    symoff = 0x400
    stroff = symoff + len(nlist)
    symtab_data = nlist + bytes(strtab)
    symtab = _cmd(0x02, struct.pack("<IIII", symoff, 4, stroff, len(strtab)))
    # iextdef = 0, nextdef = 2 → exported; iundef = 2, nundef = 2 → imported
    dysymtab = _cmd(0x0B, struct.pack("<IIIIII", 0, 0, 0, 2, 2, 2))

    commands = [_seg(), build, _dylib("/usr/lib/libcrypto.44.dylib", "3.0.20"),
                _dylib("/System/Library/Frameworks/Security.framework/Versions/A/Security",
                       "1.0.0"), rpath, uuid, symtab, dysymtab, main]
    if encrypted:
        commands.append(_cmd(0x2C, struct.pack("<III", 0x200, 0x100, 1)))

    signature = b""
    if signed:
        entitlements_xml = (b'<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">'
                            b"<dict><key>com.apple.security.get-task-allow</key><true/>"
                            b"<key>com.apple.security.cs.allow-jit</key><true/></dict></plist>")
        entitlement_blob = struct.pack(">II", 0xFADE7171, 8 + len(entitlements_xml)) \
            + entitlements_xml
        identifier = b"com.acme.toolkit\x00"
        team = b"ACME1234\x00"
        # CodeDirectory: 9 u32 fields, then hashSize/hashType/platform/pageSize,
        # then spare2 + scatterOffset, then teamOffset — the team string follows
        team_offset = 52
        ident_offset = team_offset + len(team)
        directory = (struct.pack(">IIIIIIIII", 0xFADE0C02, 0, 0x20400,
                                 0x10000 if hardened else 0, 0, ident_offset, 0, 0, 0x2000)
                     + bytes([32, 2, 0, 12]) + struct.pack(">II", 0, 0)
                     + struct.pack(">I", team_offset) + team + identifier)
        directory = struct.pack(">II", 0xFADE0C02, len(directory)) + directory[8:]
        blob = (struct.pack(">III", 0xFADE0CC0, 0, 2)
                + struct.pack(">II", 0, 28)
                + struct.pack(">II", 5, 28 + len(directory))
                + directory + entitlement_blob)
        blob = struct.pack(">II", 0xFADE0CC0, len(blob)) + blob[8:]
        signature = blob

    header_size = 32
    if signature:
        commands.append(_cmd(0x1D, struct.pack("<II", 0, 0)))
    commands_size = sum(len(cmd) for cmd in commands)
    if signature:
        # the signature lives after the symbol table, so its offsets are known
        # before assembly and the placeholder can be filled in place
        sig_offset = max(header_size + commands_size, symoff) + len(symtab_data)
        last = len(commands) - 1
        commands[last] = _cmd(0x1D, struct.pack("<II", sig_offset, len(signature)))
        commands_size = sum(len(cmd) for cmd in commands)
    data = bytearray(header_size) + bytearray(b"".join(commands))
    while len(data) < symoff:
        data.append(0)
    data.extend(symtab_data)
    if signature:
        assert len(data) == sig_offset, (len(data), sig_offset)  # offsets line up
        data.extend(signature)
    if constants:
        # plant the table past everything else and point __TEXT,__text at it; the
        # command keeps its length, so the assembled file does not shift
        replacement = _seg(len(data), len(constants))
        assert len(replacement) == len(commands[0])
        data[header_size:header_size + len(replacement)] = replacement
        data.extend(constants)
    struct.pack_into("<IIIIIIII", data, 0, 0xFEEDFACF, 0x0100000C, 0, 2,
                     len(commands), commands_size, flags, 0)
    return bytes(data)


def _rpm(*, name: str = "acme-crypto", version: str = "3.4.5", release: str = "1.el9",
         license_: str = "Apache-2.0", payload_compressor: str = "gzip",
         requires: tuple = ("libcrypto.so.3", "libssl.so.3"), cpio_payload: bytes = b"",
         rsa_signature: bytes | None = None, sha256_digest: bytes | None = None) -> bytes:
    """A real RPM: lead + signature header + header (with NAME/VERSION/…) + payload."""
    import gzip as _gzip

    def _header(tags: list[tuple[int, int, bytes, int]]) -> bytes:
        store = bytearray()
        entries = b""
        for tag, dtype, payload, count in tags:
            entries += struct.pack(">IIII", tag, dtype, len(store), count)
            store.extend(payload)
        head = (b"\x8e\xad\xe8\x01" + bytes(4)
                + struct.pack(">II", len(tags), len(store)) + entries + bytes(store))
        return head + bytes((8 - len(head) % 8) % 8)

    def _string(text: str) -> bytes:
        return text.encode() + b"\x00"

    signature_tags: list[tuple[int, int, bytes, int]] = [
        (1004, 7, bytes.fromhex("00" * 16), 16),
        (1000, 4, struct.pack(">I", 4096), 1)]
    if rsa_signature:
        signature_tags.append((268, 7, rsa_signature, len(rsa_signature)))
    if sha256_digest:
        signature_tags.append((273, 8, sha256_digest, len(sha256_digest)))
    signature = _header(signature_tags)
    main = _header([
        (1000, 6, _string(name), 1),
        (1001, 6, _string(version), 1),
        (1002, 6, _string(release), 1),
        (1014, 6, _string(license_), 1),
        (1011, 6, _string("Acme Corp"), 1),
        (1022, 6, _string("x86_64"), 1),
        (1049, 8, b"".join(_string(item) for item in requires), len(requires)),
        (1047, 8, b"".join(_string("acme-crypto.so") for _ in requires), len(requires)),
        (1125, 6, _string(payload_compressor), 1),
    ])
    payload = _gzip.compress(cpio_payload, mtime=0) if cpio_payload else b""
    return (b"\xed\xab\xee\xdb" + bytes(4) + struct.pack(">HH", 3, 0) + bytes(84)
            + signature + main + payload)


def _deb(*, control: bytes, data: list[tuple[str, bytes]] | None = None,
         control_name: str = "control.tar.gz") -> bytes:
    """A real .deb: ar archive with control.tar.* and data.tar.* members."""
    import gzip as _gzip

    def _ar_member(name: str, payload: bytes) -> bytes:
        header = f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{0o100644:<8}{len(payload):<10}`\n`".encode()
        header = header[:58] + b"`\n"
        return header + payload + (b"\n" if len(payload) % 2 else b"")

    control_tar = _tar([("./control", control)])
    data_tar = _tar(data or [("usr/bin/acme", b"\x7fELF\x02\x01\x01\x00" + bytes(64))])
    return (b"!<arch>\n"
            + _ar_member("debian-binary", b"2.0\n")
            + _ar_member(control_name, _gzip.compress(control_tar, mtime=0))
            + _ar_member("data.tar.gz", _gzip.compress(data_tar, mtime=0)))


def _write_tmp(tmp_path, name: str, payload: bytes):
    target = tmp_path / name
    target.write_bytes(payload)
    return target


def _cpio(members: list[tuple[str, bytes]]) -> bytes:
    """newc cpio archive (initramfs payload)."""
    out = b""
    for index, (name, payload) in enumerate(members, start=1):
        name_bytes = name.encode() + b"\x00"
        header = b"070701" + b"".join(
            f"{value:08x}".encode() for value in (
                index, 0o100644, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name_bytes), 0))
        out += header + name_bytes
        out += b"\x00" * ((4 - len(out) % 4) % 4)
        out += payload
        out += b"\x00" * ((4 - len(out) % 4) % 4)
    trailer = b"070701" + b"".join(
        f"{value:08x}".encode() for value in (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0))
    out += trailer + b"TRAILER!!!\x00"
    out += b"\x00" * ((4 - len(out) % 4) % 4)
    return out


def _java_class(version_major: int = 61) -> bytes:
    """A class file whose constant pool names a crypto provider and a transform."""
    pool: list[bytes] = []
    utf8: dict[str, int] = {}

    def _utf8(text: str) -> int:
        if text not in utf8:
            pool.append(bytes([1]) + struct.pack(">H", len(text)) + text.encode())
            utf8[text] = len(pool)
        return utf8[text]

    cipher = _utf8("javax/crypto/Cipher")
    transform = _utf8("AES/GCM/NoPadding")
    _utf8("MD5")
    provider = _utf8("org/bouncycastle/jce/provider/BouncyCastleProvider")
    name_type = _utf8("getInstance")
    descriptor = _utf8("(Ljava/lang/String;)V")
    class_ref = len(pool) + 1
    pool.append(bytes([7]) + struct.pack(">H", cipher))                      # Class
    pool.append(bytes([7]) + struct.pack(">H", provider))                    # Class
    name_type_ref = len(pool) + 1
    pool.append(bytes([12]) + struct.pack(">HH", name_type, descriptor))     # NameAndType
    pool.append(bytes([10]) + struct.pack(">HH", class_ref, name_type_ref))  # Methodref
    pool.append(bytes([8]) + struct.pack(">H", transform))                   # String
    body = b"".join(pool)
    return (b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, version_major)
            + struct.pack(">H", len(pool) + 1) + body + b"\x00\x21\x00\x00\x00\x00")


def _tar(members: list[tuple[str, bytes]]) -> bytes:
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in members:
            import tarfile as tf

            info = tf.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _firmware(*, model: str = "FriendlyARM NanoPi R5S",
              compatible=(b"rockchip,rk3568", b"rockchip,rk3568-nanopi-r5s")) -> bytes:
    strings_block = b"\x00".join([b"model", model.encode()] + [b"compatible", *compatible, b""])
    strings_off = 64
    total = strings_off + len(strings_block)
    dtb = (struct.pack(">IIIIIIIIII", 0xD00DFEED, total, strings_off, 0, 0, 0, 0, 0, total - 8, 0)
           + b"\x00" * (strings_off - 40) + strings_block)
    uimage = (struct.pack(">IIIIIII", 0x27051956, 0, 0, len(dtb) + 64, 0, 0, 0x0F)
              + b"Linux-6.1-image\x00".ljust(32, b"\x00") + b"\x00" * 4)
    return uimage + dtb + b"hsqs" + b"\x00" * 40 + b"\x1f\x8b\x08" + b"\x00" * 60


# ------------------------------------------------------------------ tests --- #
def test_identify_uses_magic_not_extension(tmp_path):
    elf = _elf64()
    fake = tmp_path / "not-an-executable.txt"
    fake.write_bytes(elf)
    assert bs.identify(elf, "not-an-executable.txt")["format"] == "elf"
    assert bs.identify(b"#!/bin/sh\necho hi\n", "script.sh")["format"] == "raw"
    # "MZ" alone is not a PE — the PE signature must sit at e_lfanew
    doc = b"MZ" + b"\x00" * 200
    assert bs.identify(doc, "doc.doc")["format"] == "raw"


def test_elf_dynamic_symbols_and_comment():
    elf = _elf64(deps=("libc.so.6", "libssl.so.3"), soname="libtest.so.1",
                 comment=b"GCC: (Ubuntu 13.2.0) 13.2.0\x00",
                 build_id=bytes.fromhex("7d90f38412d00023e58392b03612a24b62fcaede"),
                 imports=("EVP_EncryptInit_ex", "malloc"), exports=("SSL_new", "OPENSSL_init"))
    parsed = bs.parse_elf(elf)
    assert parsed["bits"] == 64 and parsed["arch"] == "x86-64-64"
    assert parsed["type"] == "shared-library" and parsed["stripped"] is True
    assert parsed["libraries"] == ["libc.so.6", "libssl.so.3"]
    assert parsed["soname"] == "libtest.so.1"
    assert parsed["compiler"][0].startswith("GCC:")
    assert parsed["build_id"] == "7d90f38412d00023e58392b03612a24b62fcaede"
    assert parsed["imports"] == ["EVP_EncryptInit_ex", "malloc"]
    assert parsed["exports"] == ["SSL_new", "OPENSSL_init"]
    assert parsed["import_count"] == 2 and parsed["export_count"] == 2


def test_elf_runpath_and_go_buildinfo():
    go = _go_section("github.com/acme/paymentsvc", "v1.4.2",
                     [("github.com/golang-jwt/jwt/v5", "v5.2.0"), ("golang.org/x/crypto", "v0.31.0")])
    elf = _elf64(deps=("libc.so.6",), runpath="/tmp/app/lib", go_section=go)
    parsed = bs.parse_elf(elf)
    assert parsed["rpath"] == ["/tmp/app/lib"]
    assert parsed["go"]["go_version"] == "go1.21.5"
    assert parsed["go"]["module"] == "github.com/acme/paymentsvc"
    assert parsed["go"]["module_version"] == "v1.4.2"
    assert [dep["name"] for dep in parsed["go"]["dependencies"]] == [
        "github.com/golang-jwt/jwt/v5", "golang.org/x/crypto"]

    result = bs.sbom_result({"target": "x", "binaries": [{"name": "paymentsvc", "path": "paymentsvc",
                                                          "sha256": "ab", "format": "elf",
                                                          "arch": "x86-64", "go": parsed["go"],
                                                          "crypto": {}, "findings": []}],
                             "binaries_scanned": 1, "files_walked": 1})
    names = {pkg["name"] for pkg in result["packages"]}
    assert {"github.com/acme/paymentsvc", "github.com/golang-jwt/jwt/v5",
            "golang.org/x/crypto"} <= names
    purls = {pkg.get("purl") for pkg in result["packages"]}
    assert "pkg:golang/golang.org/x/crypto@v0.31.0" in purls
    edges = {(edge["from"], edge["to"]) for edge in result["dependencies"]}
    assert ("paymentsvc", "github.com/acme/paymentsvc") in edges
    assert ("github.com/acme/paymentsvc", "golang.org/x/crypto") in edges


def test_go_buildinfo_absent_section_is_not_invented():
    elf = _elf64(deps=("libc.so.6",))
    assert "go" not in bs.parse_elf(elf)


def test_pe_imports_subsystem_and_dotnet():
    parsed = bs.parse_pe(_pe(imports=("KERNEL32.dll", "CRYPT32.dll")))
    assert parsed["machine"] == "x86-64" and parsed["bits"] == 64
    assert parsed["subsystem"] == "console"
    assert parsed["libraries"] == ["KERNEL32.dll", "CRYPT32.dll"]
    assert parsed["sections"] == [".rdata"]
    assert bs.parse_pe(_pe(dotnet=True)).get("dotnet") is True


def test_ar_resolves_gnu_long_names(tmp_path):
    long_name = b"a-very-long-member-name-that-needs-the-table.o/\n"

    def _member(name: bytes, payload: bytes) -> bytes:
        header = (name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
                  + b"100644".ljust(8) + str(len(payload)).ljust(10).encode() + b"`\n")
        assert len(header) == 60, len(header)
        return header + payload

    archive = (b"!<arch>\n"
               + _member(b"/", b"")                      # symbol index table
               + _member(b"//", long_name)               # GNU long-name table
               + _member(b"/0", b"\x90" * 8))
    parsed = bs.parse_ar(archive)
    assert parsed["type"] == "static-library"
    assert parsed["symbol_table_entries"] == 1
    assert [m["name"] for m in parsed["members"]] == ["a-very-long-member-name-that-needs-the-table.o"]


@pytest.mark.parametrize("name", ["demo-1.2.3-py3-none-any.whl", "lib.jar"])
def test_zip_metadata_for_wheel_and_jar(tmp_path, name):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        if name.endswith(".whl"):
            archive.writestr("demo-1.2.3.dist-info/METADATA",
                             "Name: demo\nVersion: 1.2.3\nLicense: MIT\nRequires-Dist: cryptography\n")
        else:
            archive.writestr("META-INF/maven/org.acme/demo/pom.properties",
                             "groupId=org.acme\nartifactId=demo\nversion=9.1\n")
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Version: 9.1\n")
            archive.writestr("org/acme/Demo.class", "not-a-real-class")
            archive.writestr("org/bouncycastle/jce/Provider.class", "x")
    parsed = bs.parse_zip(path.read_bytes(), path.name)
    if name.endswith(".whl"):
        assert parsed["type"] == "python-wheel"
        assert parsed["python"]["name"] == "demo" and parsed["python"]["version"] == "1.2.3"
        assert parsed["python"]["license"] == "MIT"
    else:
        assert parsed["type"] == "java-archive"
        assert parsed["java"]["artifact"] == "demo" and parsed["java"]["group"] == "org.acme"
        assert parsed["java"]["version"] == "9.1"
        assert parsed["java"]["class_count"] == 2
        assert "BouncyCastle" in parsed["libraries"]


def test_firmware_chain_and_device_tree_identity(tmp_path):
    path = tmp_path / "fw.img"
    path.write_bytes(_firmware())
    record = bs.scan_file(path)
    formats = [row["format"] for row in record["containers"]]
    assert formats[:4] == ["uimage", "dtb", "squashfs", "gzip"]
    assert record["device_tree"]["model"] == "FriendlyARM NanoPi R5S"
    assert "rockchip,rk3568" in record["device_tree"]["compatible"]
    assert record["embedded_filesystems"][0]["format"] == "squashfs"
    codes = {finding["code"] for finding in record["findings"]}
    assert "BIN-FIRMWARE-NOT-EXTRACTED" in codes
    note = next(finding["detail"] for finding in record["findings"]
                if finding["code"] == "BIN-FIRMWARE-NOT-EXTRACTED")
    assert "NOT" in note and "binwalk" in note


def test_crypto_evidence_grades_and_does_not_invent(tmp_path):
    """A symbol table full of lookalikes must not produce library claims."""
    elf = _elf64(deps=("libcrypto.so.3",),
                 imports=("EVP_sha224", "EVP_aes_128_cbc_hmac_sha256", "EVP_sha256",
                          "aes_128_gcm_init"), exports=("ossl_der_oid_id_slh_dsa_sha2_192f",),
                 strings=("OpenSSL 3.0.20 7 Apr 2026", "string::new", "something::ring::aead"))
    path = tmp_path / "libcrypto.so.3"
    path.write_bytes(elf)
    record = bs.scan_file(path)
    libraries = {row["library"]: row for row in record["crypto"]["libraries"]}
    assert libraries["OpenSSL"]["version"] == "3.0.20"
    assert "RustCrypto" not in libraries
    suppressed = {row["library"] for row in record["crypto"]["suppressed_libraries"]}
    assert "RustCrypto" in suppressed
    assert any("single lexical hit" in row["reason"] or "substring" in row["reason"]
               for row in record["crypto"]["suppressed_libraries"])
    # counts as evidence that crypto exists, without claiming a specific library
    reasons = {finding["code"] for finding in record["findings"]}
    assert "BIN-CRYPTO-NO-VERSION" not in reasons


def test_weak_primitive_and_quantum_findings(tmp_path):
    elf = _elf64(deps=("libcrypto.so.3",), exports=("RSA_sign", "MD5Init", "EVP_md5", "EVP_sha1"))
    path = tmp_path / "libweak.so"
    path.write_bytes(elf)
    record = bs.scan_file(path)
    codes = {finding["code"]: finding for finding in record["findings"]}
    assert codes["BIN-WEAK-PRIMITIVE-PRESENT"]["severity"] == "HIGH"
    assert "MD5" in codes["BIN-WEAK-PRIMITIVE-PRESENT"]["detail"]
    assert codes["BIN-QUANTUM-VULNERABLE"]["severity"] == "MEDIUM"
    assert "RSA" in codes["BIN-QUANTUM-VULNERABLE"]["algorithms"]


def test_pqc_and_ecc_are_classified_separately(tmp_path):
    """X25519 is classical ECC: it accelerates migration, it is not post-quantum."""
    path = tmp_path / "node"
    path.write_bytes(_elf64(exports=("x25519_keygen", "ml_kem_encapsulate", "ml_dsa_verify")))
    record = bs.scan_file(path)
    crypto = record["crypto"]
    assert "ml_kem" in crypto["pqc_markers"] and "ml_dsa" in crypto["pqc_markers"]
    assert "X25519" in crypto["ecc_markers"] or "x25519" in crypto["ecc_markers"]
    assert "X25519" not in crypto["pqc_markers"]
    # a binary that has both must say so rather than reading as fully migrated
    detail = next(finding["detail"] for finding in record["findings"]
                  if finding["code"] == "BIN-PQC-CAPABLE")
    assert "ALSO references classical primitives" in detail


def test_static_binary_without_deps_is_reported_as_static(tmp_path):
    elf = bytearray(_elf64())
    struct.pack_into("<H", elf, 16, 2)          # ET_EXEC
    struct.pack_into("<H", elf, 18, 0x28)       # ARM
    path = tmp_path / "statically-linked"
    path.write_bytes(bytes(elf))
    parsed = bs.parse_elf(bytes(elf))
    assert parsed["machine"] == "ARM"
    record = bs.scan_file(path)
    assert record["arch"].startswith("ARM")


def test_scan_path_walks_parses_and_respects_caps(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "libdemo.so").write_bytes(_elf64(deps=("libc.so.6",),
                                                            strings=("OpenSSL 1.1.1w 11 Sep 2023",)))
    (tmp_path / "plain.txt").write_text("nothing to see")
    (tmp_path / "app.bin").write_bytes(_firmware())
    scan = bs.scan_path(tmp_path)
    assert scan["binaries_scanned"] == 2
    assert scan["by_format"]["elf"] == 1 and scan["by_format"]["uimage"] == 1
    paths = {record["path"] for record in scan["binaries"]}
    assert "nested/libdemo.so" in paths and "app.bin" in paths
    assert scan["limits"]["truncated"] is False

    capped = bs.scan_path(tmp_path, max_binaries=1)
    assert capped["binaries_scanned"] == 1 and capped["limits"]["truncated"] is True


def test_raw_files_need_crypto_evidence_to_be_reported(tmp_path):
    journal = tmp_path / "image.dd"
    journal.write_bytes(b"\x00" * 64 + b"nothing here" + b"\x00" * 64)
    assert bs.scan_file(journal) is None
    journal.write_bytes(b"\x00" * 64 + b"Linked against libcrypto.so.3 (OpenSSL 3.0.20 7 Apr 2026)"
                        + b"\x00" * 64)
    record = bs.scan_file(journal)
    assert record is not None and record["format"] == "raw"
    assert record["parse_note"] and "string-level evidence" in record["parse_note"]
    assert any(finding["code"] == "BIN-NOT-PARSED" for finding in record["findings"])


def test_a_broken_header_is_reported_rather_than_invented(tmp_path):
    """RPM and Java class files are parsed now — a damaged one says so."""
    rpm = tmp_path / "pkg.rpm"
    rpm.write_bytes(b"\xed\xab\xee\xdb" + b"\x00" * 200)
    record = bs.scan_file(rpm)
    assert record["format"] == "rpm" and record["parsed"] is True
    assert "NAME tag was absent" in record["parse_note"]

    cls = tmp_path / "Demo.class"
    # magic + version, constant_pool_count = 5, then an unknown pool tag
    cls.write_bytes(b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 61) + struct.pack(">H", 5)
                    + b"\x63" + bytes(40))
    class_record = bs.scan_file(cls)
    assert class_record["format"] == "java-class"
    assert class_record["java"]["constant_pool_truncated_at"] == 1
    assert any(finding["code"] == "BIN-PARTIAL-PARSE" for finding in class_record["findings"])


def test_strings_and_entropy_are_bounded():
    blob = b"\x01\x02" + b"A" * 40 + b"\x00" + b"B" * 12 + b"\xff" * 4
    strings = bs.extract_strings(blob, min_len=6)
    assert strings == ["A" * 40, "B" * 12]
    assert bs.extract_strings(b"C" * 100, limit=3) == ["C" * 100]
    assert bs.entropy(b"\x00" * 1000) == 0.0
    assert 7.9 < bs.entropy(bytes(range(256)) * 4) <= 8.0


def test_version_and_eol_helpers():
    assert bs.version_tuple("3.0.20") == (3, 0, 20)
    assert bs.version_tuple("no-version") == ()
    assert bs.is_end_of_life("OpenSSL", "1.1.1w") is True
    assert bs.is_end_of_life("OpenSSL", "3.0.20") is False
    assert bs.is_end_of_life("Node.js", "22.22.3") is False
    assert bs.is_end_of_life("Unknown", "1.0.0") is False      # never guessed
    assert bs.is_end_of_life("OpenSSL", None) is False


def test_cbom_document_is_ingestible(tmp_path):
    from cbom.inventory import is_crypto_component, records_from_bom, validate_document

    path = tmp_path / "libcrypto.so.3"
    path.write_bytes(_elf64(deps=("libc.so.6",),
                            exports=("EVP_EncryptInit_ex", "RSA_sign", "EVP_sha256"),
                            strings=("OpenSSL 3.0.20 7 Apr 2026", "ML-KEM-768")))
    scan = bs.scan_path(tmp_path)
    document = bs.cbom_document(scan, target="host crypto", created_by="tester")
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.5"
    assert document["metadata"]["component"]["name"] == "host crypto"
    assert validate_document(document)["ok"] is True
    assert all(is_crypto_component(component) for component in document["components"])
    records = records_from_bom(document)
    assert records, "CBOM must yield crypto inventory records"
    by_name = {record["name"]: record for record in records}
    assert "RSA" in by_name and by_name["RSA"]["algorithm"] == "RSA"
    rsa = next(c for c in document["components"] if c["name"] == "RSA")
    assert rsa["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    aes = next((c for c in document["components"] if c["name"].startswith("AES")), None)
    if aes is not None:
        assert "nistQuantumSecurityLevel" not in aes["cryptoProperties"]["algorithmProperties"]
    pqc = next(c for c in document["components"] if c["name"] == "ML-KEM-768")
    assert pqc["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert any(prop["name"] == "cryptoscan:found-in" for prop in pqc["properties"])


def test_sbom_adapter_feeds_the_standard_renderer(tmp_path):
    from container_scanner.reports.sbom import build_sbom
    from devsecops import sbom_scan

    path = tmp_path / "libcrypto.so.3"
    path.write_bytes(_elf64(deps=("libc.so.6",), exports=("EVP_EncryptInit_ex",),
                            strings=("OpenSSL 3.0.20 7 Apr 2026",)))
    result = bs.sbom_result(bs.scan_path(tmp_path))
    bom = sbom_scan.enrich_bom(build_sbom(result), result, created_by="tester")
    names = {component["name"] for component in bom["components"]}
    assert "OpenSSL" in names and "libcrypto.so.3" in names
    openssl = next(c for c in bom["components"] if c["name"] == "OpenSSL")
    assert openssl["version"] == "3.0.20"
    assert openssl["properties"] and any(p["name"] == "cryptoscan:crypto-library"
                                         for p in openssl["properties"])
    binary = next(c for c in bom["components"] if c["name"] == "libcrypto.so.3")
    assert binary["bom-ref"] == "cryptoscan:binary/libcrypto.so.3"
    assert binary["hashes"][0]["alg"] == "SHA-256"
    assert bom["metadata"]["authors"] == [{"name": "tester"}]


def test_sbom_adapter_keeps_scan_metadata_visible(tmp_path):
    (tmp_path / "app.bin").write_bytes(_firmware())
    result = bs.sbom_result(bs.scan_path(tmp_path))
    assert result["target_kind"] == "binary"
    assert result["binaries_scanned"] == 1
    assert result["by_format"] == {"uimage": 1}
    assert any(finding["code"] == "BIN-FIRMWARE-NOT-EXTRACTED" for finding in result["findings"])
    assert result["vulnerabilities"] == []          # never invented without a feed


def test_documented_gaps_are_stated_not_hidden():
    """The module must say what it does not do — the docstring is the contract."""
    text = bs.__doc__ or ""
    assert "does **not** unpack squashfs" in text
    assert "identified-but-not-parsed" in text
    assert "graded" in text


def test_diff_does_not_confuse_a_binary_with_a_library(tmp_path):
    """A binary named `openssl` and the `OpenSSL` library are two components.

    Keying a diff on the component name alone would report one of them and hide
    the other, so a re-scan could look unchanged while a binary appeared.
    """
    from devsecops.sbom_assurance import diff_boms
    from container_scanner.reports.sbom import build_sbom
    from devsecops import sbom_scan

    directory = tmp_path / "bin"
    directory.mkdir()
    (directory / "libcrypto.so.3").write_bytes(
        _elf64(exports=("EVP_EncryptInit_ex",), strings=("OpenSSL 3.0.20 7 Apr 2026",)))
    before = sbom_scan.enrich_bom(build_sbom(bs.sbom_result(bs.scan_path(directory))),
                                  bs.sbom_result(bs.scan_path(directory)))
    (directory / "openssl").write_bytes(
        _elf64(exports=("EVP_EncryptInit_ex",), strings=("OpenSSL 3.0.20 7 Apr 2026",)))
    # the same scan result drives both sides, so the collision is what changes
    after = sbom_scan.enrich_bom(build_sbom(bs.sbom_result(bs.scan_path(directory))),
                                 bs.sbom_result(bs.scan_path(directory)))
    report = diff_boms(before, after)
    names = {row["name"] for row in report["added"]}
    assert "openssl" in names, report
    assert report["summary"]["added"] >= 1
    # the versioned library is still tracked by name, so upgrades stay upgrades
    assert all(row["ref"] for row in report["added"])


def test_diff_still_detects_an_upgrade_by_name():
    from devsecops.sbom_assurance import diff_boms

    def _bom(version, ref):
        return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
            {"type": "library", "name": "requests", "version": version, "bom-ref": ref}]}

    report = diff_boms(_bom("2.31.0", "pkg:pypi/requests@2.31.0"),
                       _bom("2.32.0", "pkg:pypi/requests@2.32.0"))
    assert report["verdict"] == "UPDATED"
    assert [(c["name"], c["direction"]) for c in report["changed"]] == [("requests", "upgrade")]


# ----------------------------------------------- turn-30 depth: ELF/PE/java -- #
def test_elf_program_headers_and_hardening_flags():
    """PT_INTERP, PT_GNU_STACK and PT_GNU_RELRO are read, not guessed."""
    elf = _elf64(deps=("libc.so.6",), dynamic_extra=((24, 0),), soname="libacme.so.1",
                 segments=((3, 4, 0x2000, b"/lib64/ld-linux-x86-64.so.2"),
                           (1, 4, 0x1000, b"x" * 32),
                           (0x6474E552, 4, 0x3000, b"y" * 16),
                           (0x6474E551, 6, 0, b"")))
    parsed = bs.parse_elf(elf)
    assert parsed["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert "gnu_relro" in parsed["segments"] and "gnu_stack" in parsed["segments"]
    assert parsed["executable_stack"] is False
    hardening = parsed["hardening"]
    assert hardening["nx"] is True and hardening["relro"] is True
    assert hardening["full_relro"] is True          # PT_GNU_RELRO + BIND_NOW
    assert hardening["pie"] is True                 # ET_DYN


def test_elf_executable_stack_is_reported_as_a_finding(tmp_path):
    path = tmp_path / "legacy"
    path.write_bytes(_elf64(segments=((1, 5, 0x400000, b"x" * 16), (0x6474E551, 7, 0, b""))))
    record = bs.scan_file(path)
    assert record["executable_stack"] is True
    codes = {finding["code"] for finding in record["findings"]}
    assert "BIN-EXECUTABLE-STACK" in codes
    assert any(finding["severity"] == "HIGH" for finding in record["findings"])


def test_elf_symbol_version_floor_becomes_a_finding(tmp_path):
    """A crypto soname with no embedded version is a floor, labelled as one."""
    path = tmp_path / "app"
    path.write_bytes(_elf64(deps=("libc.so.6", "libcrypto.so.3"),
                            symbol_versions={"libcrypto.so.3": ["OPENSSL_3.0.0", "OPENSSL_3.0.3"]},
                            exports=("EVP_EncryptInit_ex",)))
    record = bs.scan_file(path)
    assert record["symbol_versions"] == {"libcrypto.so.3": ["OPENSSL_3.0.0", "OPENSSL_3.0.3"]}
    floor = [f for f in record["findings"] if f["code"] == "BIN-CRYPTO-VERSION-FLOOR"]
    assert floor and "3.0.3" in floor[0]["detail"]
    assert "cannot be matched" in floor[0]["detail"]


def test_elf_crypto_constants_grade_as_constant_match(tmp_path):
    """A complete table in .rodata is stronger evidence than a symbol name."""
    from devsecops.crypto_constants import aes_inverse_sbox, aes_sbox

    path = tmp_path / "libacme.so"
    path.write_bytes(_elf64(soname="libacme.so",
                            constants=aes_sbox() + aes_inverse_sbox()))
    record = bs.scan_file(path)
    constants = record["crypto_constants"]
    assert [row["algorithm"] for row in constants] == ["AES", "AES"]
    assert {row["table"] for row in constants} == {"S-box", "inverse S-box"}
    assert all(row["section"] == ".rodata" and row["complete"] for row in constants)
    evidence = [row for row in record["crypto"]["algorithm_evidence"] if row["name"] == "AES"]
    assert evidence and evidence[0]["strongest_evidence"] == "CONSTANT_MATCH"
    assert evidence[0]["confidence"] >= 0.9
    assert evidence[0]["constant_level"] == "CONSTANT_FULL"
    level = record["crypto"]["constant_evidence"]["AES"]
    assert level["complete_tables"] == 2 and level["bytes_matched"] == 512
    assert level["reason"] == "two or more complete tables present"
    codes = {finding["code"] for finding in record["findings"]}
    assert "BIN-CRYPTO-CONSTANT-TABLE" in codes


def test_an_eight_byte_prefix_is_reported_as_weak_evidence_not_as_aes(tmp_path):
    """The count decides the claim: two words of a table prove nothing."""
    from universal_crypto.binary_engine import CRYPTO_CONSTANTS

    path = tmp_path / "libfragment.so"
    path.write_bytes(_elf64(soname="libfragment.so", constants=CRYPTO_CONSTANTS["AES"]))
    record = bs.scan_file(path)
    level = record["crypto"]["constant_evidence"]["AES"]
    assert level["level"] == "CONSTANT_WEAK" and level["bytes_matched"] == 8
    assert level["complete_tables"] == 0
    assert "AES" not in [row["name"] for row in record["crypto"]["algorithm_evidence"]]
    partial = [finding for finding in record["findings"]
               if finding["code"] == "BIN-CRYPTO-CONSTANT-PARTIAL"]
    assert len(partial) == 1 and partial[0]["severity"] == "LOW"
    assert "weak evidence" in partial[0]["detail"]
    assert "not used to claim an implementation" in partial[0]["detail"]


def test_pe_delay_imports_resources_and_version_strings():
    """RT_VERSION gives the publisher and the product, not just a version."""
    parsed = bs.parse_pe(_pe_rich())
    assert parsed["delay_imports"] == ["CRYPT32.dll"]
    assert "CRYPT32.dll" in parsed["libraries"]
    info = parsed["version_info"]
    assert info["version"] == "9.1.0.0"
    assert info["vendor"] == "Acme Corp" and info["product"] == "Acme Toolkit"
    resources = parsed["resources"]
    assert resources["strings"]["OriginalFilename"] == "acme.exe"
    assert resources["translation"] == [{"language": 1033, "codepage": 1200}]
    assert resources["file_type"] == "application"


def test_pe_debug_directory_and_signature_presence():
    parsed = bs.parse_pe(_pe_rich())
    assert parsed["debug"]["pdb"].endswith("acme.pdb")
    assert parsed["debug"]["pdb_guid"] == "00112233445566778899aabbccddeeff"
    assert parsed["debug"]["pdb_age"] == 3
    signature = parsed["signature"]
    assert signature["present"] is True and signature["type"] == "pkcs7"
    assert "validity and chain are NOT verified" in signature["note"]


def test_pe_unsigned_and_rich_header_are_reported():
    signed = bs.parse_pe(_pe_rich())
    unsigned = bs.parse_pe(_pe_rich(signed=False))
    assert unsigned["signature"]["present"] is False
    assert signed["linker"]["entries"] == [{"product_id": 267, "build": 11783, "count": 5}]


def test_pe_uefi_subsystem_marks_the_image():
    parsed = bs.parse_pe(_pe_rich(subsystem=12))
    assert parsed["subsystem"] == "efi-runtime-driver"
    assert parsed["uefi"] is True and parsed["type"] == "efi-image"


def test_pe_clr_metadata_reports_the_framework():
    parsed = bs.parse_pe(_pe_rich(clr=True))
    assert parsed["dotnet"]["framework_version"] == "v4.0.30319"
    assert parsed["framework"] == ".NET v4.0.30319"


def test_unsigned_pe_raises_an_informational_finding(tmp_path):
    path = tmp_path / "acme.exe"
    path.write_bytes(_pe_rich(signed=False))
    record = bs.scan_file(path)
    assert any(finding["code"] == "BIN-UNSIGNED-PE" and finding["severity"] == "INFO"
               for finding in record["findings"])


def test_packer_signature_is_named_and_flagged(tmp_path):
    path = tmp_path / "packed.bin"
    path.write_bytes(b"\x7fELF\x02\x01\x01\x00" + bytes(56) + b"UPX!UPX!" + bytes(512))
    record = bs.scan_file(path)
    assert record["packer"]["name"] == "UPX"
    assert any(finding["code"] == "BIN-PACKED" for finding in record["findings"])


def test_a_class_file_with_a_bad_pool_entry_says_where_it_stopped():
    """A truncated constant pool is a partial read, not a clean parse."""
    data = bytearray(_java_class())
    data[10] = 0x63                       # first pool entry: unknown tag
    record = bs.parse_bytes(bytes(data), name="Broken.class")
    java = record["java"]
    assert java["constant_pool_truncated_at"] == 1
    assert java["class_version"] == "61.0"
    assert java.get("classes") is None or "Cipher" not in " ".join(java.get("classes") or [])


def test_jvm_internal_names_are_marker_evidence():
    """Class files name packages with slashes; JCA evidence must not be dropped."""
    crypto = bs.crypto_evidence(b"", ["javax/crypto/Cipher"],
                                imports=["javax/crypto/Cipher"])
    libraries = {row["library"]: row for row in crypto["libraries"]}
    assert "JCA-JCE" in libraries, crypto["suppressed_libraries"]
    assert libraries["JCA-JCE"]["evidence_classes"] == ["marker"]


def test_java_class_constant_pool_is_read(tmp_path):
    path = tmp_path / "Crypto.class"
    path.write_bytes(_java_class())
    record = bs.scan_file(path)
    assert record["format"] == "java-class" and record["parsed"] is True
    assert "javax/crypto/Cipher" in record["java"]["classes"]
    assert "BouncyCastle" in record["libraries"]
    assert "MD5" in record["crypto"]["weak_primitives"]
    assert record["java"]["class_version"] == "61.0"
    assert "AES/GCM/NoPadding" in record["java"]["strings"]
    assert any(finding["code"] == "BIN-WEAK-PRIMITIVE-CLASS" for finding in record["findings"])


def test_pe_mitigations_are_read_from_dllcharacteristics():
    """PE hardening parity with ELF: ASLR, DEP, CFG, SEH, GS from the header."""
    hardening = bs.parse_pe(_pe_rich(dll_characteristics=0x4160))["hardening"]
    assert hardening["aslr"] is True and hardening["dep"] is True
    assert hardening["high_entropy_va"] is True and hardening["cfg"] is True
    assert hardening["seh"] is True and hardening["isolation"] is True
    # 0x0400 (NO_SEH) and 0x0200 (NO_ISOLATION) are inverted when set
    legacy = bs.parse_pe(_pe_rich(dll_characteristics=0x0600))["hardening"]
    assert legacy["seh"] is False and legacy["isolation"] is False
    assert legacy["aslr"] is False and legacy["dep"] is False


def test_pe_load_config_says_whether_gs_and_cfg_are_live():
    """DllCharacteristics declares the policy; the load config says it is wired up."""
    parsed = bs.parse_pe(_pe_rich(load_config=True))
    assert parsed["load_config"]["security_cookie"] == "0x140002000"
    assert parsed["load_config"]["guard_flags"] == 0x100
    assert parsed["hardening"]["gs"] is True
    assert parsed["hardening"]["cfg_instrumented"] is True

    without = bs.parse_pe(_pe_rich(load_config=True, security_cookie=0, guard_flags=0))
    assert without["hardening"]["gs"] is False
    assert without["hardening"]["cfg_instrumented"] is False


def test_unmitigated_pe_raises_aslr_dep_cfg_and_gs_findings(tmp_path):
    path = tmp_path / "legacy.exe"
    path.write_bytes(_pe_rich(dll_characteristics=0x0000, load_config=True, security_cookie=0,
                              guard_flags=0))
    record = bs.scan_file(path)
    findings = {finding["code"]: finding for finding in record["findings"]}
    assert findings["BIN-NO-ASLR"]["severity"] == "MEDIUM"
    assert findings["BIN-NO-DEP"]["severity"] == "HIGH"
    assert findings["BIN-NO-CFG"]["severity"] == "LOW"
    assert findings["BIN-NO-STACK-CANARY"]["severity"] == "LOW"
    assert "not position independent" in findings["BIN-NO-ASLR"]["title"]

    # a fully mitigated image raises none of them
    hardened = tmp_path / "hardened.exe"
    hardened.write_bytes(_pe_rich(dll_characteristics=0x4160, load_config=True))
    codes = {finding["code"] for finding in bs.scan_file(hardened)["findings"]}
    assert not codes & {"BIN-NO-ASLR", "BIN-NO-DEP", "BIN-NO-CFG", "BIN-NO-STACK-CANARY"}


def test_pe_version_info_names_the_publisher():
    """RT_VERSION is where a PE states who built it and what it is."""
    parsed = bs.parse_pe(_pe_rich())
    info = parsed["version_info"]
    assert info["version"] == "9.1.0.0"
    assert info["vendor"] == "Acme Corp" and info["product"] == "Acme Toolkit"
    strings = parsed["resources"]["strings"]
    assert strings["CompanyName"] == "Acme Corp"
    assert strings["ProductName"] == "Acme Toolkit"
    assert strings["OriginalFilename"] == "acme.exe"
    assert strings["LegalCopyright"] == "Copyright Acme"
    assert parsed["resources"]["translations"] == ["040904b0"]


def test_pe_delay_loaded_dependency_is_a_finding(tmp_path):
    """A delayed import still runs code, so it is reported rather than dropped."""
    path = tmp_path / "acme.exe"
    path.write_bytes(_pe_rich())
    record = bs.scan_file(path)
    assert record["delay_imports"] == ["CRYPT32.dll"]
    assert "CRYPT32.dll" in record["libraries"]
    finding = [f for f in record["findings"] if f["code"] == "BIN-DELAYED-IMPORT"][0]
    assert finding["severity"] == "INFO"
    assert "still loaded" in finding["detail"]


def test_ambiguous_platform_constructors_are_not_promoted():
    """CC_SHA256 names a primitive; CCCryptorCreate and EVP_CIPHER_CTX_new do not."""
    ambiguous = bs.crypto_evidence(b"", [], imports=["CCCryptorCreate", "EVP_CIPHER_CTX_new"])
    assert not any("platform API" in source
                   for row in ambiguous["algorithm_evidence"] for source in row["sources"])
    clear = bs.crypto_evidence(b"", [], imports=["CC_SHA256", "getrandom"])
    evidence = {row["name"]: row for row in clear["algorithm_evidence"]}
    assert evidence["SHA-256"]["strongest_evidence"] == "IMPORT"
    assert evidence["CSPRNG"]["strongest_evidence"] == "IMPORT"
    assert all("platform API" in row["sources"][0] for row in evidence.values())


def test_elf_section_names_are_listed_with_hardening():
    """The section table shows what a binary still carries; hardening reads it."""
    parsed = bs.parse_elf(_elf64(deps=("libc.so.6",), imports=("__stack_chk_fail",),
                                 symbol_versions={"libc.so.6": ["GLIBC_2.34"]},
                                 segments=((1, 5, 0x400000, b"x" * 16), (0x6474E551, 6, 0, b""))))
    assert ".gnu.version_r" in parsed["sections"]
    assert ".dynsym" in parsed["sections"] and ".shstrtab" in parsed["sections"]
    assert len(parsed["sections"]) == len(set(parsed["sections"]))
    assert parsed["segments"] == ["load", "gnu_stack"]
    assert parsed["hardening"]["nx"] is True
    assert parsed["hardening"]["canary"] is True


def test_macho_dylibs_build_version_and_symbols():
    """Linked dylibs carry their own versions; the symbol table names the calls."""
    parsed = bs.parse_macho(_macho())
    assert parsed["arch"] == "AArch64" and parsed["type"] == "executable"
    versions = parsed["dylib_versions"]
    assert versions["/usr/lib/libcrypto.44.dylib"]["current"] == "3.0.20"
    assert versions["/usr/lib/libcrypto.44.dylib"]["compat"] == "3.0.0"
    assert parsed["platform"] == "macOS"
    assert parsed["minimum_os"] == "13.0.1" and parsed["sdk"] == "14.0.4"
    assert parsed["rpath"] == ["@executable_path/../Frameworks"]
    assert parsed["sections"] == ["__TEXT,__text"]
    # dyld leading underscores are stripped, so symbols key the crypto tables
    assert parsed["exports"] == ["EVP_EncryptInit_ex", "CC_SHA256"]
    assert sorted(parsed["imports"]) == ["CCCryptorCreate", "SecKeyEncrypt"]
    assert parsed["stripped"] is False
    assert parsed["hardening"]["pie"] is True


def test_macho_code_signature_identity_and_entitlements():
    parsed = bs.parse_macho(_macho())
    signature = parsed["signature"]
    assert signature["present"] is True
    assert signature["identifier"] == "com.acme.toolkit"
    assert signature["team_id"] == "ACME1234"
    assert signature["hash_type"] == "sha256"
    assert signature["hardened_runtime"] is True
    assert "com.apple.security.get-task-allow" in signature["entitlements"]
    assert "validity, certificate chain and notarisation are NOT verified" in signature["note"]


def test_macho_signature_and_entitlement_findings(tmp_path):
    path = tmp_path / "acme-tool"
    path.write_bytes(_macho(signed=False))
    record = bs.scan_file(path)
    codes = {finding["code"] for finding in record["findings"]}
    assert "BIN-UNSIGNED-MACHO" in codes

    (tmp_path / "signed-tool").write_bytes(_macho(hardened=False))
    signed = bs.scan_file(tmp_path / "signed-tool")
    findings = {finding["code"]: finding for finding in signed["findings"]}
    assert findings["BIN-ENTITLEMENT"]["severity"] == "MEDIUM"
    assert findings["BIN-ENTITLEMENT"]["entitlement"] == "com.apple.security.get-task-allow"
    assert "BIN-NO-HARDENED-RUNTIME" in findings


def test_encrypted_macho_is_reported_as_such(tmp_path):
    path = tmp_path / "protected"
    path.write_bytes(_macho(encrypted=True))
    record = bs.scan_file(path)
    assert record["encrypted"] is True
    finding = [f for f in record["findings"] if f["code"] == "BIN-ENCRYPTED"][0]
    assert finding["severity"] == "HIGH"
    assert "structurally incomplete" in finding["detail"]


def test_macho_stack_exec_flag_is_a_finding(tmp_path):
    path = tmp_path / "legacy"
    path.write_bytes(_macho(flags=0x200000 | 0x20000))
    record = bs.scan_file(path)
    assert record["hardening"]["stack_exec"] is True
    assert any(finding["code"] == "BIN-EXECUTABLE-STACK" for finding in record["findings"])


def test_fat_macho_lists_every_slice(tmp_path):
    thin = _macho()
    fat = (b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
           + struct.pack(">IIIII", 0x0100000C, 0, 0x1000, len(thin), 14)     # arm64
           + struct.pack(">IIIII", 0x01000007, 3, 0x1000 + len(thin), len(thin), 14)
           + bytes(0x1000 - 48) + thin + thin)
    parsed = bs.parse_macho(fat)
    assert parsed["type"] == "universal"
    assert parsed["slices"] == ["AArch64", "x86-64"]
    assert parsed["parsed_slice"] == "AArch64"
    assert parsed["dylib_versions"]["/usr/lib/libcrypto.44.dylib"]["current"] == "3.0.20"


def test_macho_symbols_feed_crypto_evidence(tmp_path):
    """CommonCrypto/OpenSSL symbols are the Mach-O equivalent of an import table."""
    path = tmp_path / "acme-tool"
    path.write_bytes(_macho())
    record = bs.scan_file(path)
    evidence = {row["name"]: row for row in record["crypto"]["algorithm_evidence"]}
    assert "SHA-256" in evidence, record["crypto"]["algorithm_evidence"]
    assert evidence["SHA-256"]["strongest_evidence"] == "SYMBOL"
    assert "CC_SHA256" in evidence["SHA-256"]["sources"][0]
    libraries = {row["library"] for row in record["crypto"]["libraries"]}
    assert "Apple CommonCrypto" in libraries


def test_uimage_header_is_decoded_and_crcs_are_verified(tmp_path):
    """A firmware blob states its OS/arch/type/compression — and its own checksums."""
    path = tmp_path / "firmware.img"
    path.write_bytes(_uimage())
    record = bs.scan_file(path)
    image = record["uimage"]
    assert image["os"] == "linux" and image["arch"] == "arm64"
    assert image["image_type"] == "ramdisk" and image["compression"] == "gzip"
    assert image["name"] == "Acme Linux-6.1.38"
    assert image["load_address"] == hex(0x80008000)
    assert image["payload_offset"] == 64
    assert image["header_crc_verified"] is True
    assert image["data_crc_verified"] is True
    assert image["built"].startswith("20")
    assert record["arch"] == "arm64"
    assert not [f for f in record["findings"] if f["code"].startswith("BIN-UIMAGE")]


def test_uimage_crc_mismatches_are_reported_not_ignored(tmp_path):
    """A checksum mismatch is a fact about the file, so it is a finding."""
    broken_header = tmp_path / "broken-header.img"
    broken_header.write_bytes(_uimage(break_header_crc=True))
    record = bs.scan_file(broken_header)
    finding = [f for f in record["findings"] if f["code"] == "BIN-UIMAGE-CRC"][0]
    assert record["uimage"]["header_crc_verified"] is False
    assert "modified or damaged" in finding["detail"]

    broken_payload = tmp_path / "broken-payload.img"
    broken_payload.write_bytes(_uimage(declare_size=1 << 20))
    record = bs.scan_file(broken_payload)
    codes = {f["code"] for f in record["findings"]}
    assert "BIN-UIMAGE-PAYLOAD" in codes
    payload_finding = [f for f in record["findings"] if f["code"] == "BIN-UIMAGE-PAYLOAD"][0]
    assert payload_finding["severity"] == "HIGH"
    assert record["uimage"]["truncated"] is True


def test_uimage_compression_governs_whether_the_payload_is_opened(tmp_path):
    """The header's compression field decides if the ramdisk is followed, and how."""
    inner = _cpio([("lib/libcrypto.so.3", _elf64(soname="libcrypto.so.3"))])
    path = tmp_path / "firmware.img"
    path.write_bytes(_uimage(payload=gzip.compress(inner), comp_id=1))
    result = bs.sbom_result(bs.scan_path(tmp_path, recursive=True))
    embedded = [row for row in result["binaries"] if row.get("derived_from")]
    assert [row["file_name"] for row in embedded] == ["libcrypto.so.3"]
    assert embedded[0]["path"] == "firmware.img@64!lib/libcrypto.so.3"

    refused = tmp_path / "zstd.img"
    refused.write_bytes(_uimage(payload=b"\x28\xb5\x2f\xfd" + bytes(64), comp_id=6))
    scan = bs.scan_file(refused)
    reasons = [r for c in scan.get("containers_followed") or [] for r in (c.get("refused") or [])]
    assert any("zstd" in str(reason.get("format")) for reason in reasons)


# ------------------------------------------------ turn-30 depth: RPM/deb --- #
def test_rpm_signature_header_decides_whether_the_package_is_signed():
    """A digest tag is integrity metadata; only RSA/DSA/PGP says "signed"."""
    digest = bytes(range(32))
    unsigned = bs.parse_rpm(_rpm())
    assert unsigned["signed"] is False
    assert unsigned["signature"]["present"] is False
    assert unsigned["signature"]["digest_algorithms"] == ["md5"]
    assert unsigned["signature"]["digests"]["md5"] == "00" * 16

    signed = bs.parse_rpm(_rpm(rsa_signature=b"\x01\x02\x03", sha256_digest=digest))
    assert signed["signed"] is True
    assert signed["signature"]["kinds"] == ["rsa", "sha256"] or "rsa" in signed["signature"]["kinds"]
    assert signed["signature"]["digests"]["sha256"] == digest.hex()


def test_unsigned_rpm_is_a_finding(tmp_path):
    path = tmp_path / "acme-crypto.rpm"
    path.write_bytes(_rpm())
    record = bs.scan_file(path)
    finding = [f for f in record["findings"] if f["code"] == "BIN-RPM-UNSIGNED"][0]
    assert finding["severity"] == "MEDIUM"
    assert "provenance cannot be established" in finding["detail"]

    path.write_bytes(_rpm(rsa_signature=b"\x01\x02\x03", sha256_digest=bytes(range(32))))
    signed_record = bs.scan_file(path)
    assert signed_record["signed"] is True
    assert not [f for f in signed_record["findings"] if f["code"] == "BIN-RPM-UNSIGNED"]


def test_rpm_header_is_parsed_into_a_package():
    parsed = bs.parse_rpm(_rpm())
    assert (parsed["name"], parsed["version"], parsed["release"]) == ("acme-crypto", "3.4.5", "1.el9")
    assert parsed["license"] == "Apache-2.0" and parsed["vendor"] == "Acme Corp"
    assert parsed["payload_compression"] == "gzip"
    assert parsed["requirename"] == ["libcrypto.so.3", "libssl.so.3"]
    assert parsed["libraries"] == ["libcrypto.so.3", "libssl.so.3"]


def test_rpm_payload_cpio_is_followed_to_the_binary_inside(tmp_path):
    inner = _elf64(soname="libacme.so", exports=("EVP_EncryptInit_ex",),
                   strings=("OpenSSL 3.0.20 7 Apr 2026",))
    path = tmp_path / "acme-crypto.rpm"
    path.write_bytes(_rpm(cpio_payload=_cpio([("usr/lib64/libacme.so", inner),
                                              ("usr/share/doc/README", b"plain text")])))
    record = bs.scan_file(path)
    container = record["containers_followed"][0]
    assert container["inner_format"] == "cpio" and container["members_listed"] == 3
    assert container["parsed"] == 1
    embedded = record["embedded"][0]
    assert embedded["path"].endswith("!usr/lib64/libacme.so")
    assert embedded["derived_from"] == str(path)
    assert embedded["depth"] == 1
    assert [row["library"] for row in embedded["crypto"]["libraries"]] == ["OpenSSL"]
    assert any(finding["code"] == "BIN-EMBEDDED-CRYPTO" for finding in record["findings"])


def test_rpm_packages_inside_are_reported():
    record = bs.parse_rpm(_rpm())
    record = dict(record, path="acme.rpm", name="acme.rpm")
    packages = bs._record_packages(record)
    assert packages and packages[0]["manager"] == "rpm"
    assert packages[0]["license"] == "Apache-2.0"


def test_deb_without_a_detached_signature_says_so_without_crying_wolf(tmp_path):
    """Absent `_gpgorigin` is a provenance signal, not evidence of tampering."""
    path = tmp_path / "acme-tools.deb"
    path.write_bytes(_deb(control=b"Package: acme-tools\nVersion: 2.4.0\nArchitecture: amd64\n"))
    record = bs.scan_file(path)
    summary = (record.get("containers_followed") or [{}])[0]
    assert summary.get("package_signed") is False
    finding = [f for f in record["findings"] if f["code"] == "BIN-DEB-UNSIGNED"][0]
    assert finding["severity"] == "LOW"
    assert "repository metadata" in finding["detail"]


def test_deb_control_file_identifies_the_package(tmp_path):
    control = (b"Package: acme-crypto\nVersion: 1.2.3\nArchitecture: amd64\n"
               b"Maintainer: Acme <ops@acme.example>\nDepends: libssl3 (>= 3.0), libc6\n"
               b"Description: Acme crypto helper\n long form line\n")
    path = tmp_path / "acme-crypto.deb"
    path.write_bytes(_deb(control=control))
    record = bs.scan_file(path)
    packages = bs._record_packages(record)
    assert packages == [{"name": "acme-crypto", "version": "1.2.3", "manager": "deb",
                         "arch": "amd64", "depends": ["libssl3", "libc6"]}]
    assert any("deb control read" in row for row in record["containers_followed"][0]["opened"])


# ------------------------------------------------ turn-30 depth: extraction -- #
def test_tar_gz_member_is_parsed_with_provenance(tmp_path):
    import gzip

    inner = _elf64(soname="libacme.so", exports=("EVP_EncryptInit_ex",))
    path = tmp_path / "bundle.tar.gz"
    path.write_bytes(gzip.compress(_tar([("lib/libacme.so", inner), ("README", b"hello")]), mtime=0))
    record = bs.scan_file(path)
    container = record["containers_followed"][0]
    assert container["format"] == "gzip" and container["inner_format"] == "ustar"
    assert container["members_listed"] == 2 and container["parsed"] == 1
    embedded = record["embedded"][0]
    assert embedded["format"] == "elf" and embedded["derived_from"] == str(path)
    import hashlib

    assert embedded["sha256"] == hashlib.sha256(inner).hexdigest()
    assert any(finding["code"] == "BIN-CONTAINER-FOLLOWED" for finding in record["findings"])


def test_a_bare_cpio_archive_is_opened(tmp_path):
    """A cpio that is not wrapped in gzip is still an initramfs-style container."""
    path = tmp_path / "firmware.img"
    path.write_bytes(_cpio([("lib/libcrypto.so.3", _elf64()), ("bin/busybox", _elf64())]))
    assert bs.identify(path.read_bytes(), "")["format"] == "cpio"
    scan = bs.scan_path(tmp_path, recursive=True)
    result = bs.sbom_result(scan)
    embedded = [row for row in result["binaries"] if row.get("derived_from")]
    assert len(embedded) == 2, [row["path"] for row in result["binaries"]]
    names = sorted(row["file_name"] for row in embedded)
    assert names == ["busybox", "libcrypto.so.3"]
    for row in embedded:
        assert row["derived_from"] == "firmware.img"
        assert row["path"].startswith("firmware.img!")
        assert row["format"] == "elf"


def test_cpio_old_ascii_format_is_identified_but_not_claimed_as_parsed(tmp_path):
    """An odc archive is identified and refused honestly, not silently skipped."""
    path = tmp_path / "old.cpio"
    path.write_bytes(b"070707" + bytes(64))
    record = bs.parse_bytes(path.read_bytes(), name="old.cpio")
    assert record["format"] == "cpio-odc"
    assert record["parsed"] is False
    assert "repack it with `cpio -H newc`" in record["parse_note"]


def test_initramfs_cpio_members_are_listed(tmp_path):
    import gzip

    archive = _cpio([("bin/busybox", b"\x7fELF\x02\x01\x01\x00" + bytes(120)),
                     ("etc/init.d/rcS", b"#!/bin/sh\n")])
    path = tmp_path / "initramfs.gz"
    path.write_bytes(gzip.compress(archive, mtime=0))
    record = bs.scan_file(path)
    container = record["containers_followed"][0]
    assert container["inner_format"] == "cpio"
    assert [member["name"] for member in container["members"]][:2] == ["bin/busybox", "etc/init.d/rcS"]


def test_refused_compression_states_the_reason(tmp_path):
    path = tmp_path / "firmware.zst"
    path.write_bytes(b"\x28\xb5\x2f\xfd" + bytes(600))
    record = bs.scan_file(path)
    refused = record["containers_followed"][0]["refused"]
    assert refused and "no stdlib zstd decoder" in refused[0]["reason"]
    assert any(finding["code"] == "BIN-CONTAINER-REFUSED" for finding in record["findings"])


def test_extraction_budget_stops_a_compression_bomb(tmp_path):
    import gzip

    path = tmp_path / "bomb.gz"
    path.write_bytes(gzip.compress(b"\x00" * (8 * 1024 * 1024), mtime=0))
    record = bs.scan_file(path)
    container = record["containers_followed"][0]
    # it opens what fits the budget and says so, instead of trying to hold it all
    assert container["opened"] and "B" in container["opened"][0]
    assert bs.MAX_EXTRACT_BYTES <= 96 * 1024 * 1024


def test_an_embedded_file_gets_the_same_evidence_as_a_loose_one(tmp_path):
    """Depth must not dilute evidence: constants inside a container still count."""
    import gzip

    from universal_crypto.binary_engine import CRYPTO_CONSTANTS

    from devsecops.crypto_constants import aes_sbox

    inner = _elf64(soname="libacme.so", constants=aes_sbox() + CRYPTO_CONSTANTS["MD5"])
    (tmp_path / "libacme.so").write_bytes(inner)
    (tmp_path / "bundle.tar.gz").write_bytes(gzip.compress(_tar([("lib/libacme.so", inner)]), mtime=0))
    scan = bs.scan_path(tmp_path)
    records = bs._flatten_records(scan["binaries"])
    loose = [row for row in records if row["path"] == "libacme.so"][0]
    embedded = [row for row in records if row["path"].endswith("!lib/libacme.so")][0]
    # the AES S-box is complete; the bare eight-byte MD5 prefix also matches the
    # reverse view of SHA-1's H, so those bytes are reported as ambiguous rather
    # than as a second algorithm
    assert {row["algorithm"] for row in embedded["crypto_constants"]} == {"AES", "MD5", "SHA-1"}
    assert embedded["crypto_constants"][0]["complete"] is True
    ambiguous = [(row["algorithm"], row["ambiguous_with"], row["bytes_matched"])
                 for row in embedded["crypto_constants"] if row["ambiguous_with"]]
    assert ambiguous == [("SHA-1", ["MD5"], 8)]
    md5 = [row for row in embedded["crypto_constants"] if row["algorithm"] == "MD5"][0]
    assert md5["ambiguous_with"] == [] and "8 of 16 table bytes present" in md5["evidence"]
    assert [row["algorithm"] for row in embedded["crypto_constants"]] == \
        [row["algorithm"] for row in loose["crypto_constants"]]
    assert embedded["crypto"]["algorithms"] == loose["crypto"]["algorithms"]
    evidence = {row["name"]: row["strongest_evidence"] for row in embedded["crypto"]["algorithm_evidence"]}
    assert evidence.get("AES") == "CONSTANT_MATCH"
    cbom = bs.cbom_document(scan)
    aes = [row for row in cbom["components"] if row["name"] == "AES"][0]
    locations = {occurrence["location"] for occurrence in aes["evidence"]["occurrences"]}
    assert locations == {"libacme.so", "bundle.tar.gz!lib/libacme.so"}


def test_embedded_crypto_reaches_the_sbom_and_cbom(tmp_path):
    import gzip

    inner = _elf64(soname="libacme.so", exports=("EVP_EncryptInit_ex",),
                   strings=("OpenSSL 3.0.20 7 Apr 2026",))
    (tmp_path / "bundle.tar.gz").write_bytes(gzip.compress(_tar([("lib/libacme.so", inner)]), mtime=0))
    scan = bs.scan_path(tmp_path)
    result = bs.sbom_result(scan)
    paths = [row["path"] for row in result["binaries"]]
    assert any("!lib/libacme.so" in path for path in paths)
    derived = [row for row in result["binaries"] if "!lib/libacme.so" in row["path"]][0]
    assert derived["derived_from"].endswith("bundle.tar.gz") and derived["depth"] == 1
    cbom = bs.cbom_document(scan)
    libraries = [component["name"] for component in cbom["components"]]
    assert "OpenSSL" in libraries, cbom["components"]
    openssl = [component for component in cbom["components"] if component["name"] == "OpenSSL"][0]
    provenance = {row["name"]: row["value"] for row in openssl["properties"]}
    assert provenance["cryptoscan:derived-from"].endswith("bundle.tar.gz")
    assert provenance["cryptoscan:depth"] == "1"
    assert provenance["cryptoscan:found-in"].endswith("!lib/libacme.so")


# --------------------------------------------------------------------------- #
# constants in PE and Mach-O, plus the trigger rule
# --------------------------------------------------------------------------- #

def test_pe_sections_are_searched_for_constant_tables():
    """The constant search is not an ELF-only capability."""
    parsed = bs.parse_pe(_pe_rich(constants=cc.aes_sbox() + cc.sha256_k()))
    deep = parsed["_constant_evidence"]
    assert deep["searched_bytes"] >= len(cc.aes_sbox()) + len(cc.sha256_k())
    found = {(row["algorithm"], row["table"]) for row in parsed["crypto_constants"]}
    assert ("AES", "S-box") in found and ("SHA-256", "K") in found
    assert all(row["section"] == ".rdata" for row in parsed["crypto_constants"])

    # and a PE without tables still says how much was looked at
    quiet = bs.parse_pe(_pe_rich())
    assert quiet["crypto_constants"] == [] and quiet["_constant_evidence"]["searched_bytes"] >= 0x1000


def test_macho_sections_are_searched_for_constant_tables():
    parsed = bs.parse_macho(_macho(constants=cc.blowfish_p()))
    deep = parsed["_constant_evidence"]
    assert deep["searched_bytes"] > 0
    found = {(row["algorithm"], row["table"]) for row in parsed["crypto_constants"]}
    assert ("Blowfish", "P-array") in found


def test_sbom_reports_how_much_was_searched_not_only_what_was_found(tmp_path):
    """`searched_bytes: 0` and "nothing there" are different answers."""
    (tmp_path / "libacme.so").write_bytes(
        _elf64(soname="libacme.so", constants=cc.aes_sbox() + cc.sha256_k()))
    (tmp_path / "libquiet.so").write_bytes(_elf64(soname="libquiet.so"))
    result = bs.sbom_result(bs.scan_path(tmp_path))
    totals = result["constants"]
    # both ELFs were searched, even though only one had a table in it
    assert totals["artefacts_searched"] == 2 and totals["searched_bytes"] > 0
    assert totals["complete_tables"] == 2 and totals["partial_matches"] == 0
    assert totals["algorithms"] == ["AES", "SHA-256"]
    rows = {row["file_name"]: row["constants"] for row in result["binaries"]}
    assert rows["libacme.so"]["tables_matched"] == 2
    assert rows["libquiet.so"]["tables_matched"] == 0 and rows["libquiet.so"]["searched_bytes"] > 0


def test_a_shared_table_is_reported_as_an_ambiguity_not_a_confirmation():
    """A complete table that another algorithm also stores may not name anything."""
    parsed = bs.parse_elf(_elf64(soname="libshared.so", constants=cc.sha256_h()))
    record = dict(parsed)
    record["crypto"] = bs.crypto_evidence(b"", [], constants=parsed.get("_constant_blobs") or [],
                                          constant_evidence=parsed["_constant_evidence"])
    by_code = {finding["code"]: finding for finding in bs._constant_findings(record)}
    shared = by_code["BIN-CRYPTO-CONSTANT-SHARED"]
    assert shared["severity"] == "LOW" and shared["algorithm"] == "BLAKE2s"
    assert shared["ambiguous_with"] == ["SHA-256"]
    assert "byte order" in shared["detail"]
    # and the algorithm whose own table it is, is reported normally
    assert by_code["BIN-CRYPTO-CONSTANT-TABLE"]["algorithm"] == "SHA-256"
    assert by_code["BIN-CRYPTO-CONSTANT-TABLE"]["severity"] == "INFO"
    # the ambiguity is not allowed into the SBOM's algorithm claim
    record["path"] = "libshared.so"
    assert bs._named_constant_algorithms(record) == ["SHA-256"]


def test_a_trigger_cannot_be_a_run_of_zeros():
    """Keccak's first round constant is 01 then zeros — that is not a fingerprint."""
    assert cc.keccak_rc()[:8] == b"\x01" + bytes(7)
    # every prefix of the table is that repetitive, so the whole table is required
    table = cc.ConstantTable("SHA-3", "round constants", cc.keccak_rc(), 8)
    assert table.prefix == table.data
    assert cc.scan_constants([(".rodata", cc.keccak_rc()[:32])])["tables"] == []
    assert cc.scan_constants([(".rodata", cc.keccak_rc())])["tables"][0]["complete"] is True
    # padding full of zeros must not match anything
    noise = cc.scan_constants([(".rodata", bytes(4096))])
    assert noise["tables"] == [] and noise["engine_blobs"] == []
    # and nor may a byte of the pattern followed by zeros
    assert cc.scan_constants([(".rodata", b"\x01" + bytes(255))])["tables"] == []


def test_every_table_trigger_is_long_enough_to_be_evidence():
    """A trigger either discriminates (distinct bytes) or is the whole table."""
    for table in cc.constant_tables():
        prefix = table.prefix
        assert prefix == table.data[:len(prefix)]
        assert len(prefix) >= min(len(table.data), cc.TABLE_TRIGGER)
        assert (len(set(prefix)) >= cc.TRIGGER_MIN_DISTINCT
                or prefix == table.data), (table.algorithm, table.table, prefix)
