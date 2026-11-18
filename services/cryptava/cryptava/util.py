"""Small shared helpers: the host root, bounded reads, the command allowlist."""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 — argv lists only, shell=False, allowlisted binaries
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

#: The only programs Cryptava may execute, with the exact leading arguments each may
#: be given. Everything else is read from files. Adding one is a code change.
ALLOWED_BINARIES: dict[str, tuple[tuple[str, ...], ...]] = {
    "dmidecode": (("-t", "system"), ("-t", "memory"), ("-t", "bios")),
    "rpm": (("-qa", "--qf"),),
}

MAX_READ_BYTES = 8 * 1024 * 1024
_SAFE_ARG = re.compile(r"^[A-Za-z0-9_./:%{}\\\-=,@+ \[\]\n]*$")


class CommandRefused(RuntimeError):
    pass


@dataclass
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes = b""
    stderr: str = ""
    available: bool = True

    @property
    def ok(self) -> bool:
        return self.available and self.returncode == 0


def run_allowed(argv: Sequence[str], *, timeout: float = 15.0, stdin: bytes | None = None) -> CommandResult:
    """Run one allowlisted command. Never a shell; refused arguments never spawn."""
    if not argv:
        raise CommandRefused("empty command")
    binary, args = argv[0], tuple(argv[1:])
    prefixes = ALLOWED_BINARIES.get(binary)
    if prefixes is None:
        raise CommandRefused(f"{binary!r} is not an allowlisted binary")
    if not any(args[: len(prefix)] == prefix for prefix in prefixes):
        raise CommandRefused(f"{binary} {' '.join(args[:3])}… is not an allowlisted invocation")
    for arg in args:
        if not _SAFE_ARG.match(arg):
            raise CommandRefused(f"argument {arg!r} contains characters Cryptava never passes")
    path = shutil.which(binary)
    if path is None:
        return CommandResult(tuple(argv), 127, b"", f"{binary}: not installed", available=False)
    try:
        done = subprocess.run(  # nosec B603 — allowlisted argv, shell=False
            [path, *args], input=stdin, capture_output=True, timeout=timeout, check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(argv), 124, b"", f"{binary}: timed out after {timeout}s")
    except OSError as exc:
        return CommandResult(tuple(argv), 126, b"", f"{binary}: {exc}")
    return CommandResult(tuple(argv), done.returncode, done.stdout,
                         done.stderr.decode("utf-8", "replace")[:500])


@dataclass
class HostView:
    """Where the host's files, processes and sysfs are, as seen from the agent.

    On a server ``root`` is ``/``. In a Kubernetes DaemonSet the node's filesystem is
    mounted (read-only) at ``/host`` and ``root`` is ``/host``. As a sidecar sharing a
    container's PID namespace, ``root`` is ``/proc/1/root``.
    """

    root: Path = Path("/")
    proc: Path = Path("/proc")
    sys: Path = Path("/sys")
    notes: list[str] = field(default_factory=list)

    def path(self, absolute: str | os.PathLike) -> Path:
        text = str(absolute)
        if not text.startswith("/"):
            raise ValueError(f"host paths are absolute, got {text!r}")
        if str(self.root) == "/":
            return Path(text)
        return Path(str(self.root).rstrip("/") + text)

    def resolve(self, absolute: str, *, max_hops: int = 40) -> str:
        """Follow symlinks *inside* the host root and return the host-absolute path.

        ``os.path.realpath`` cannot be used: under ``/proc/1/root`` or ``/host`` an
        absolute symlink target (``/usr/lib/libssl.so.3``) would be resolved against
        the agent's own filesystem instead of the host's.
        """
        parts = [p for p in absolute.split("/") if p not in ("", ".")]
        resolved: list[str] = []
        hops = 0
        while parts:
            part = parts.pop(0)
            if part == "..":
                if resolved:
                    resolved.pop()
                continue
            candidate = "/" + "/".join(resolved + [part])
            try:
                target = os.readlink(self.path(candidate))
            except OSError:
                resolved.append(part)
                continue
            hops += 1
            if hops > max_hops:
                return candidate
            if target.startswith("/"):
                resolved = []
            parts = [p for p in target.split("/") if p not in ("", ".")] + parts
        return "/" + "/".join(resolved)

    def host_path(self, absolute: str) -> Path:
        """Agent-side path for a host path, with symlinks followed inside the host root."""
        if str(self.root) == "/":
            return Path(absolute)
        return self.path(self.resolve(absolute))

    def read_bytes(self, absolute: str, *, limit: int = MAX_READ_BYTES) -> bytes | None:
        try:
            with open(self.host_path(absolute), "rb") as handle:
                return handle.read(limit)
        except OSError:
            return None

    def read_text(self, absolute: str, *, limit: int = MAX_READ_BYTES) -> str | None:
        data = self.read_bytes(absolute, limit=limit)
        return None if data is None else data.decode("utf-8", "replace")

    def exists(self, absolute: str) -> bool:
        try:
            return self.host_path(absolute).exists()
        except OSError:
            return False

    def glob(self, absolute_dir: str, pattern: str) -> list[str]:
        base = self.path(absolute_dir)
        try:
            found = sorted(base.glob(pattern))
        except OSError:
            return []
        prefix = len(str(self.root).rstrip("/")) if str(self.root) != "/" else 0
        return [str(item)[prefix:] or "/" for item in found]

    def walk_files(self, absolute_dir: str, *, max_depth: int = 4, max_files: int = 5000,
                   suffixes: Iterable[str] | None = None) -> list[str]:
        """Bounded directory walk returning host-absolute paths."""
        start = self.path(absolute_dir)
        wanted = tuple(s.lower() for s in suffixes) if suffixes else None
        out: list[str] = []
        prefix = len(str(self.root).rstrip("/")) if str(self.root) != "/" else 0
        base_depth = str(start).rstrip("/").count("/")
        for current, dirs, files in os.walk(start, followlinks=False):
            depth = current.rstrip("/").count("/") - base_depth
            if depth >= max_depth:
                dirs[:] = []
            dirs.sort()
            for name in sorted(files):
                if wanted and not name.lower().endswith(wanted):
                    continue
                out.append(os.path.join(current, name)[prefix:])
                if len(out) >= max_files:
                    return out
        return out

    def sys_text(self, relative: str) -> str | None:
        try:
            value = (self.sys / relative).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        return value or None

    def proc_text(self, relative: str, *, limit: int = MAX_READ_BYTES) -> str | None:
        try:
            with open(self.proc / relative, "rb") as handle:
                return handle.read(limit).decode("utf-8", "replace")
        except OSError:
            return None

    def proc_text_or_reason(self, relative: str, *, limit: int = MAX_READ_BYTES) -> tuple[str | None, str | None]:
        """(text, None) | (None, "denied") | (None, "gone") — a process that exited
        mid-scan is not an access gap and must not turn the CBOM PARTIAL."""
        try:
            with open(self.proc / relative, "rb") as handle:
                return handle.read(limit).decode("utf-8", "replace"), None
        except PermissionError:
            return None, "denied"
        except OSError:
            return None, "gone"


def clean(value: object) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split()).strip()
    if not text or text.lower() in {"to be filled by o.e.m.", "default string", "not specified",
                                     "none", "unknown", "system serial number", "0", "n/a",
                                     "not applicable", "o.e.m.", "oem"}:
        return None
    return text


def slug(value: str, *, limit: int = 60) -> str:
    text = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return text[:limit] or "x"
