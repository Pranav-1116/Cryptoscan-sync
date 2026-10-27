"""Canonical import bootstrap for repository scripts.

Every ``scripts/*.py`` entry point must import and call this instead of
hand-rolling its own ``sys.path`` — one path list, maintained once, so any
script can import any shared package or service::

    from _bootstrap import bootstrap

    bootstrap()
    from db.connection.session import init_db  # etc.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def path_entries() -> list[str]:
    """Match scripts/env.sh and container .pth discovery, including all BOM services.

    A hand-maintained list omitted devsecops and other API dependencies, so a
    fresh script/worker process could not import the current application.
    """
    entries = [str(path) for folder in ("shared", "services")
               for path in sorted((ROOT / folder).iterdir()) if path.is_dir()]
    return entries + [str(ROOT)]


def bootstrap() -> Path:
    """Prepend every canonical import root to ``sys.path`` (idempotent)."""
    os.environ.setdefault("CRYPTOSCAN_ROOT", str(ROOT))
    existing = set(sys.path)
    for entry in path_entries():
        if entry not in existing:
            sys.path.insert(0, entry)
            existing.add(entry)
    return ROOT
