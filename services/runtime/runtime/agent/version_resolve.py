"""Resolve the *real* upstream version of a mapped TLS library.

soname numbers are ABI tags, not release versions, and judging risk from them
produces false positives:

- ``libgnutls.so.30`` ships with **every** GnuTLS 3.3–3.8 release (the soname
  has stayed at 30 for years), so "soname 30" does not mean "old 3.5/3.6".
- ``libnss3.so`` has no version in its name at all.
- ``libssl.so.3`` covers OpenSSL 3.0 (nearing EOL) **and** 3.1–3.5 (current).

So the mapped filename can only ever say "a 3.x OpenSSL" or "a GnuTLS using the
30 ABI". The true version lives in the OS package metadata. This module asks
the package manager (dpkg on Debian/Parrot/Ubuntu/Kali, rpm on Fedora/RHEL)
which package owns the file and what its upstream version is.

Everything is stdlib-only and tolerant: an unmanaged file (a browser's bundled
BoringSSL/NSS under ``/opt`` or a snap/flatpak mount) resolves to "unknown",
which the risk layer treats as *no verdict* rather than a false "deprecated".

Results are cached per absolute path because the same shared object is mapped
by dozens of processes.
"""

from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from shutil import which
from typing import Any

# leading dotted upstream version, e.g. "3.7.9-2+deb12u3" -> "3.7.9",
# "1:3.87.1-1" (epoch) -> "3.87.1", "3.0.15" -> "3.0.15"
_UPSTREAM_RE = re.compile(r"(\d+(?:\.\d+){1,3})")


def _run(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout:
        return None
    return out.stdout.strip()


def _upstream(package_version: str) -> str | None:
    value = package_version.strip()
    # strip an epoch such as "2:" when present
    if ":" in value and value.split(":", 1)[0].isdigit():
        value = value.split(":", 1)[1]
    match = _UPSTREAM_RE.match(value)
    return match.group(1) if match else None


@lru_cache(maxsize=1024)
def resolve_path(path: str | None) -> dict[str, Any]:
    """Map a loaded ``.so`` path to its owning package + upstream version.

    Returns ``{"package", "package_version", "version", "source"}`` where
    ``version`` is the distro-independent upstream dotted version (or ``None``
    when the file is unmanaged / version could not be determined) and
    ``source`` is ``"dpkg"``, ``"rpm"`` or ``"unmanaged"``.
    """
    empty = {"package": None, "package_version": None, "version": None, "source": "unmanaged"}
    if not path or not path.startswith("/"):
        return empty

    # Debian / Ubuntu / Parrot / Kali / Mint
    if which("dpkg-query"):
        owner = _run(["dpkg-query", "-S", path])
        if owner and ":" in owner:
            # first owning package; may be multi-arch, e.g. "libgnutls30:amd64"
            pkg = owner.splitlines()[0].split(":", 1)[0].strip()
            pkg_name = pkg.split(":", 1)[0]
            raw = _run(["dpkg-query", "-W", "-f=${Version}", pkg_name])
            if raw:
                return {
                    "package": pkg_name,
                    "package_version": raw,
                    "version": _upstream(raw),
                    "source": "dpkg",
                }

    # Fedora / RHEL / openSUSE
    if which("rpm"):
        name = _run(["rpm", "-qf", "--qf", "%{NAME}", path])
        raw = _run(["rpm", "-qf", "--qf", "%{VERSION}", path])
        if name and raw and "not owned" not in raw and "is not owned" not in raw:
            return {
                "package": name,
                "package_version": raw,
                "version": _upstream(raw),
                "source": "rpm",
            }

    return empty
