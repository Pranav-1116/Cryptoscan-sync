"""What is inside an archive, decided before anything is expanded.

The review's fourth security blocker is archive handling: zip bombs, tar bombs,
path traversal, symlink escape, device files, huge member counts, compression
bombs and malformed manifests. The scanners already bound the *expanded* size;
what was missing is a decision on the *member list* — the cheap, safe place to
refuse, because listing an archive costs a directory read and expanding it costs
whatever the attacker chose to send.

:func:`assess_members` is that decision. It takes member descriptors from any
format and returns ``ALLOW`` or ``REFUSE`` with every problem named. The
adapters (:func:`from_zip`, :func:`from_tar`) read the real headers with the
standard library, so the guard is qualified against archives that were actually
built rather than against dictionaries that look like them.

Nothing is ever extracted here. A ``REFUSE`` has already listed the members, so
the caller can record *what was refused* without touching the payload.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.archive-guard/1"

#: Member modes that must never be materialised from an untrusted archive.
DEVICE_MODE_CHARS = frozenset({"b", "c"})   # block, char
SPECIAL_MODE_CHARS = frozenset({"p", "s"})  # fifo, socket

#: ``zipfile`` S_IF* bits → the mode character the guard reads
_S_IF_CHARS: dict[int, str] = {0o120000: "l", 0o040000: "d", 0o060000: "b", 0o020000: "c",
                               0o010000: "p", 0o140000: "s"}

#: ``tarfile`` type flags → the mode character the guard reads
_TAR_TYPE_CHARS: dict[bytes, str] = {tarfile.SYMTYPE: "l", tarfile.LNKTYPE: "l",
                                     tarfile.DIRTYPE: "d", tarfile.CHRTYPE: "c",
                                     tarfile.BLKTYPE: "b", tarfile.FIFOTYPE: "p",
                                     tarfile.REGTYPE: "-", tarfile.AREGTYPE: "-"}


@dataclass(frozen=True)
class ArchiveLimits:
    """The numbers an archive has to fit inside before it is considered."""

    max_members: int = 10_000
    max_member_bytes: int = 256 * 1024 * 1024
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_ratio: float = 200.0        # declared uncompressed / archive bytes
    max_name_bytes: int = 1024

    def to_dict(self) -> dict[str, Any]:
        return {"max_members": self.max_members, "max_member_bytes": self.max_member_bytes,
                "max_total_bytes": self.max_total_bytes, "max_ratio": self.max_ratio,
                "max_name_bytes": self.max_name_bytes}


DEFAULT_LIMITS = ArchiveLimits()


def _unsafe_name(name: str, *, max_name_bytes: int) -> str | None:
    """Why this member name must not be materialised, or ``None``."""
    if not name or not name.strip():
        return "the member has an empty name"
    if len(name.encode("utf-8", "replace")) > max_name_bytes:
        return f"the member name is longer than {max_name_bytes} bytes"
    if "\x00" in name:
        return "the member name contains a NUL byte, which truncates in C libraries"
    if any(ord(char) < 32 for char in name):
        return "the member name contains a control character"
    if name.startswith("/") or name.startswith("\\"):
        return f"the member name is absolute ({name!r})"
    if len(name) > 1 and name[1] == ":":
        return f"the member name carries a Windows drive letter ({name!r})"
    if "\\" in name:
        return f"the member name uses backslashes, which some extractors read as separators ({name!r})"
    parts = PurePosixPath(name.replace("\\", "/")).parts
    if ".." in parts:
        return f"the member name traverses upward ({name!r})"
    return None


def _escape_link(name: str, target: str) -> str | None:
    """Does this link's target resolve outside the archive root?"""
    if not target:
        return f"{name!r} is a link with no target"
    if target.startswith("/") or target.startswith("\\"):
        return f"{name!r} links to an absolute path ({target!r})"
    base = posixpath.dirname(name.replace("\\", "/"))
    resolved = posixpath.normpath(posixpath.join(base, target.replace("\\", "/")))
    if resolved == ".." or resolved.startswith("../"):
        return f"{name!r} links outside the archive root ({target!r} resolves to {resolved!r})"
    return None


def assess_members(members: Iterable[Mapping[str, Any]], *, archive_bytes: int | None = None,
                   limits: ArchiveLimits | None = None,
                   format_name: str = "unknown") -> dict[str, Any]:
    """Decide whether this member list may be expanded, and say why not.

    Member fields: ``name`` (required), ``size`` (uncompressed), ``compressed_size``,
    ``is_dir``, ``is_symlink``, ``is_hardlink``, ``link_target``, ``mode`` (the
    ``tarfile``/``zip`` mode character, e.g. ``"-"``, ``"d"``, ``"l"``, ``"b"``).
    """
    limits = limits or DEFAULT_LIMITS
    rows = list(members)
    problems: list[str] = []
    refused_members: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    total = 0

    def refuse(member: Mapping[str, Any], reason: str) -> None:
        refused_members.append({"name": str(member.get("name") or ""), "reason": reason})

    if len(rows) > limits.max_members:
        problems.append(f"{len(rows)} members exceeds the {limits.max_members} limit")

    for member in rows:
        name = str(member.get("name") or "")
        size = int(member.get("size") or 0)
        total += size
        bad_name = _unsafe_name(name, max_name_bytes=limits.max_name_bytes)
        if bad_name:
            refuse(member, bad_name)
            continue
        normalised = name.replace("\\", "/").lstrip("./")
        seen[normalised] = seen.get(normalised, 0) + 1
        mode = str(member.get("mode") or "")
        if mode[:1] in DEVICE_MODE_CHARS:
            refuse(member, f"{name!r} is a device node; expanding it would create one on the host")
            continue
        if mode[:1] in SPECIAL_MODE_CHARS:
            refuse(member, f"{name!r} is a fifo/socket; an archive has no business making one")
            continue
        if size > limits.max_member_bytes:
            refuse(member, f"{name!r} declares {size} bytes, over the "
                           f"{limits.max_member_bytes}-byte member limit")
            continue
        if member.get("is_symlink") or member.get("is_hardlink"):
            escape = _escape_link(name, str(member.get("link_target") or ""))
            if escape:
                refuse(member, escape)

    duplicates = sorted(name for name, count in seen.items() if count > 1)
    if duplicates:
        problems.append(f"{len(duplicates)} member name(s) appear more than once: "
                        f"{', '.join(duplicates[:3])} — a later entry silently replaces the "
                        "earlier one")
    if total > limits.max_total_bytes:
        problems.append(f"the declared uncompressed total is {total} bytes, over the "
                        f"{limits.max_total_bytes}-byte limit")
    # A ratio needs a denominator. When the whole archive was not handed over, the
    # declared compressed sizes are the only honest one — and a member list that
    # omits them yields no ratio rather than a ratio of zero.
    compressed_total = sum(int(member.get("compressed_size") or 0) for member in rows)
    denominator = archive_bytes or (compressed_total or None)
    measured = "archive" if archive_bytes else "declared compressed"
    if archive_bytes and archive_bytes > limits.max_total_bytes:
        problems.append(f"the archive itself is {archive_bytes} bytes")
    elif denominator and total and total / denominator > limits.max_ratio:
        problems.append(f"the archive declares {total} bytes from a {denominator}-byte "
                        f"{measured} size ({total / denominator:.0f}× compression), over the "
                        f"{limits.max_ratio:.0f}× ratio limit")
    if refused_members:
        problems.insert(0, f"{len(refused_members)} of {len(rows)} member(s) refused individually")

    return {
        "schema": SCHEMA,
        "format": format_name,
        "members": len(rows),
        "declared_bytes": total,
        "archive_bytes": archive_bytes,
        "compressed_bytes": compressed_total or None,
        "ratio": (round(total / denominator, 1) if denominator and total else None),
        "limits": limits.to_dict(),
        "problems": problems,
        "refused_members": refused_members,
        "verdict": "REFUSE" if problems else "ALLOW",
        "statement": (
            f"REFUSED: {_headline(problems, refused_members)}" if problems else
            f"{len(rows)} member(s), {total} declared bytes, nothing outside the root"),
    }


def _headline(problems: list[str], refused_members: list[dict[str, Any]]) -> str:
    """The one line that says why — the first member reason, not just a count."""
    if refused_members:
        first = refused_members[0]
        return f"{first['reason']} ({len(refused_members)} member(s) refused)"
    return problems[0]


# --------------------------------------------------------------------------- #
# adapters: real archives, standard library only
# --------------------------------------------------------------------------- #


def from_zip(source: bytes | str, *, limits: ArchiveLimits | None = None) -> dict[str, Any]:
    """Members of a zip, read from the central directory (nothing extracted)."""
    payload = source if isinstance(source, bytes) else None
    stream = io.BytesIO(payload) if payload is not None else source
    try:
        with zipfile.ZipFile(stream) as archive:
            members = []
            for info in archive.infolist():
                mode = (info.external_attr >> 16) & 0xFFFF
                kind = mode & 0o170000
                members.append({
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "is_dir": info.is_dir(),
                    "is_symlink": kind == 0o120000,
                    # the S_IF* bits decide whether this member is a file, a link
                    # or something the host must never materialise
                    "mode": _S_IF_CHARS.get(kind, "-"),
                })
    except (zipfile.BadZipFile, OSError) as exc:
        return {"schema": SCHEMA, "format": "zip", "verdict": "REFUSE",
                "problems": [f"the zip cannot be read: {exc}"], "members": 0,
                "refused_members": [], "statement": f"REFUSED: the zip cannot be read: {exc}"}
    size = len(payload) if payload is not None else _size_of(source)
    return assess_members(members, archive_bytes=size, limits=limits, format_name="zip")


def _size_of(path: str) -> int | None:
    try:
        import os

        return os.path.getsize(path)
    except OSError:
        return None


def from_tar(source: bytes | str, *, limits: ArchiveLimits | None = None) -> dict[str, Any]:
    """Members of a (possibly compressed) tar, read from the header chain."""
    payload = source if isinstance(source, bytes) else None
    stream = io.BytesIO(payload) if payload is not None else source
    try:
        with tarfile.open(fileobj=stream, mode="r:*") as archive:
            members = []
            for info in archive:
                members.append({
                    "name": info.name,
                    "size": int(info.size),
                    "is_dir": info.isdir(),
                    "is_symlink": info.issym(),
                    "is_hardlink": info.islnk(),
                    "link_target": info.linkname or None,
                    "mode": _TAR_TYPE_CHARS.get(info.type, "-"),
                })
    except (tarfile.TarError, OSError) as exc:
        return {"schema": SCHEMA, "format": "tar", "verdict": "REFUSE",
                "problems": [f"the tar cannot be read: {exc}"], "members": 0,
                "refused_members": [], "statement": f"REFUSED: the tar cannot be read: {exc}"}
    size = len(payload) if payload is not None else _size_of(source)
    return assess_members(members, archive_bytes=size, limits=limits, format_name="tar")


def inspect(source: bytes | str, *, limits: ArchiveLimits | None = None) -> dict[str, Any]:
    """Snapshot the magic and dispatch to the right reader."""
    payload = source if isinstance(source, bytes) else None
    head = payload[:8] if payload is not None else _read_head(source)
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return from_zip(source, limits=limits)
    if head.startswith(b"\x1f\x8b") or head.startswith(b"BZh") or head.startswith(b"\xfd7zXZ"):
        return from_tar(source, limits=limits)
    if payload is not None and len(payload) > 262 and payload[257:262] == b"ustar":
        return from_tar(source, limits=limits)
    return {"schema": SCHEMA, "format": "unknown", "verdict": "REFUSE",
            "problems": [f"the format is not recognised from its magic ({head[:4]!r})"],
            "members": 0, "refused_members": [],
            "statement": "REFUSED: the format is not recognised, so its members cannot be checked"}


def _read_head(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(512)
    except OSError:
        return b""
