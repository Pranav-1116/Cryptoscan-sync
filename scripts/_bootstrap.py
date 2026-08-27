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

_SHARED_PACKAGES = ("shared_config", "shared_logging", "shared_models")

_SERVICE_PACKAGES = (
    "agility",
    "api",
    "business_context",
    "cbom",
    "cloud_scanner",
    "container_scanner",
    "database",
    "deduplication",
    "drift",
    "evidence",
    "graph_engine",
    "network_scanner",
    "normalization",
    "ot_scanner",
    "policy",
    "quantum",
    "remediation",
    "reporting",
    "scanner",
    "vendor_intel",
    "worker",
)


def path_entries() -> list[str]:
    """The canonical import roots: shared packages first, then services."""
    entries = [str(ROOT / "shared" / name) for name in _SHARED_PACKAGES]
    entries += [str(ROOT / "services" / name) for name in _SERVICE_PACKAGES]
    entries.append(str(ROOT))
    return entries


def bootstrap() -> Path:
    """Prepend every canonical import root to ``sys.path`` (idempotent)."""
    os.environ.setdefault("CRYPTOSCAN_ROOT", str(ROOT))
    existing = set(sys.path)
    for entry in path_entries():
        if entry not in existing:
            sys.path.insert(0, entry)
            existing.add(entry)
    return ROOT
