"""Offline breached-password corpus.

A password policy that only rejects *short* and *dictionary-shaped* strings has
a blind spot: ``Tr0ub4dor&3xKcd`` is long, mixed-class and not a dictionary
word, yet it appears in public breach dumps and is on every cracking list built
from them. The only honest way to refuse those is to consult a corpus.

The corpus is an operator-supplied file, not a bundled list, because the useful
lists are large and change weekly:

* one entry per line, either a hex SHA-256 digest or ``digest:count`` /
  ``digest,count`` (the HIBP "ordered by prevalence" shape);
* ``#`` starts a comment; blank lines are ignored;
* comparison is on SHA-256 of the UTF-8 password, so the file never has to
  contain a usable password and no plaintext is loaded into memory.

Nothing here is downloaded at runtime. Absent the file the check is *off*, and
:func:`production_gap` names that as a deployment gap so it cannot pass silently.
"""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path

CORPUS_ENV = "PASSWORD_BREACH_CORPUS"

_lock = threading.Lock()
_cache: tuple[str, int, frozenset[str]] | None = None


def digest(password: str) -> str:
    """SHA-256 of the password, the only form ever compared."""
    return hashlib.sha256(str(password or "").encode("utf-8")).hexdigest()


def _parse(raw: str) -> frozenset[str]:
    entries: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.replace(",", ":").split(":", 1)[0].strip().lower()
        if len(token) == 64 and all(c in "0123456789abcdef" for c in token):
            entries.add(token)
    return frozenset(entries)


def load(path: str | Path | None = None) -> frozenset[str]:
    """The corpus, re-read when the file changes on disk."""
    global _cache
    target = Path(path or os.environ.get(CORPUS_ENV, "").strip() or "")
    if not str(target) or not target.is_file():
        return frozenset()
    try:
        mtime = int(target.stat().st_mtime)
    except OSError:  # vanished between the check and the stat
        return frozenset()
    with _lock:
        if _cache is not None and _cache[0] == str(target) and _cache[1] == mtime:
            return _cache[2]
        try:
            entries = _parse(target.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            return frozenset()
        _cache = (str(target), mtime, entries)
        return entries


def describe() -> dict[str, object]:
    """What the policy is actually using — for startup logs and drills."""
    path = os.environ.get(CORPUS_ENV, "").strip()
    entries = load()
    return {
        "configured": bool(path),
        "loaded": bool(entries),
        "path": path,
        "entries": len(entries),
    }


def is_breached(password: str) -> bool:
    """True when the password's digest is in the loaded corpus."""
    entries = load()
    if not entries:
        return False
    return digest(password) in entries


def production_gap(settings=None) -> str | None:
    """A sentence for the startup log when production has no corpus, else None.

    Returns ``None`` in non-production: a developer machine has no business
    needing a 10 GB file to run the test suite.
    """
    try:
        if settings is None:
            from api.config.settings import get_settings

            settings = get_settings()
        if not getattr(settings, "is_production", False):
            return None
    except Exception:  # noqa: BLE001 — an unreadable config is handled by startup itself
        return None
    if describe()["loaded"]:
        return None
    return (
        f"{CORPUS_ENV} is not set or contains no digests: breached-but-strong passwords "
        "are accepted. Point it at an up-to-date breach corpus to close this."
    )
